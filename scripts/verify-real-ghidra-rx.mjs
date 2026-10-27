import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { ArtifactResourceScope } from "../dist/artifacts/ArtifactResourceScope.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { readGhidraLanguageCatalog } from "../dist/ghidra/GhidraLanguageCatalog.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import {
  requireMcpOperationResult,
  requireMcpOutput,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-rx.mjs");
// Windows Ghidra P0 does not admit rx; there is no Windows lane.
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "rx raw-binary verification requires a Linux or macOS Ghidra host.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );

const RX_LANGUAGE = "rx62t:LE:32:default";
// The limitation REA reports because the RX language is a
// community SLEIGH module rather than one shipped with stock Ghidra. Keep this
// matcher aligned with the producer's wording.
const RX_COMMUNITY_MODULE_LIMITATION =
  /rx62t:LE:32:default comes from the community RX processor module [^]*it is not shipped with Ghidra/u;
// Refused-selection wording is owned by raw-binary admission (src/domain/rawBinary.ts).
const RX_ENTRY_OUTSIDE_IMAGE =
  /entry_point 0x[0-9a-f]+ must lie inside the mapped image/u;
const RX_MAPPING_PAST_WIDTH = /must fit in the rx address width/u;

const installation = await inspectVerifierGhidraInstallation({
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
// The same installation catalog reader GhidraProvider admits languages from.
const languageScope = new ArtifactResourceScope();
let rxInstalled;
try {
  rxInstalled = (
    await readGhidraLanguageCatalog(installation.installDir, languageScope)
  ).some((definition) => definition.id === RX_LANGUAGE);
} finally {
  await languageScope.close();
}
if (!rxInstalled) {
  // Refusal of an absent RX module is covered by source tests, not this lane.
  process.stdout.write(
    `skipped: ${RX_LANGUAGE} (not in the Ghidra installation catalog that REA admits)\n`,
  );
  process.exit(0);
}

const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
// Source-owned little-endian RX image. File offset 0 maps at base 0xfff00000;
// the leading data makes the entry differ from the base:
//   0xfff00000 44332211 88776655 ccbbaa99 00ffeedd   word table
//   0xfff00010 "REA-RX-FIXTURE\0\0"                   ASCII marker
//   0xfff00020 390800        bsr.w   leaf (0xfff00028)  entry
//   0xfff00023 6211          add     #0x1, r1
//   0xfff00025 02            rts
//   0xfff00026 0303          nop; nop
//   0xfff00028 fb1278563412  mov.l   #0x12345678, r1    leaf
//   0xfff0002e 02            rts
//   0xfff0002f 03            nop
//   0xfff00030 "TAIL" efbeadde                          tail data
const BASE = 0xfff00000n;
const at = (offset) => `0x${(BASE + BigInt(offset)).toString(16)}`;
const ENTRY_OFFSET = 0x20;
const LEAF_OFFSET = 0x28;
const MARKER = Buffer.from("REA-RX-FIXTURE\0\0", "latin1");
const TAIL = Buffer.from("5441494cefbeadde", "hex");
const bytes = Buffer.concat([
  Buffer.from("4433221188776655ccbbaa9900ffeedd", "hex"),
  MARKER,
  Buffer.from("3908006211020303fb1278563412" + "0203", "hex"),
  TAIL,
]);
assert.equal(bytes.length, 0x38);
assert.equal(bytes.indexOf(MARKER), 0x10);
assert.equal(bytes.indexOf(TAIL), 0x30);
const sha256 = createHash("sha256").update(bytes).digest("hex");
const base = at(0);
const entry = at(ENTRY_OFFSET);
const leaf = at(LEAF_OFFSET);
assert.equal(base, "0xfff00000");
assert.equal(entry, "0xfff00020");
assert.equal(leaf, "0xfff00028");

await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-rx-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const path = join(workspace, "image.bin");
await writeFile(path, bytes);
const entrypoint = join(root, "scripts", "rea.mjs");
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-rx-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
const rawSelection = {
  path,
  format: "raw-binary",
  architecture: "rx",
};
let report;
try {
  await client.connect(transport);
  const opened = await call("open_binary", {
    ...rawSelection,
    // Non-canonical spellings must come back canonical.
    base_address: "0xFFF00000",
    entry_point: "0xFFF00020",
    provider_id: "ghidra",
  });
  assert.equal(opened.architecture, "rx");
  assert.equal(opened.entry_point, entry);
  assert.equal(opened.base_address, base);
  const status = await call("binary_session");
  const image = evidence(await call("inspect_native_load_image"));
  const loaded = image.normalized_result;
  assert.equal(loaded.status, "verified", JSON.stringify(loaded));
  assert.equal(loaded.architecture, "rx");
  assert.equal(loaded.base_address, base);
  assert.equal(loaded.entry.address, entry);
  assert.equal(loaded.entry.file_offset, ENTRY_OFFSET);
  assert.equal(loaded.language_id, RX_LANGUAGE);
  assert.equal(loaded.compiler_spec_id, "default");
  assert.equal(loaded.file_bytes, bytes.length);
  assert.equal(loaded.observations.default_address_space, "ram");
  assert.equal(image.analysis_profile.parameters.loader, "BinaryLoader");
  assert.equal(image.analysis_profile.parameters.language_id, RX_LANGUAGE);
  assert.equal(image.analysis_profile.parameters.compiler_spec_id, "default");
  assert.equal(image.analysis_profile.parameters.entry_point, entry);
  assert.equal(image.analysis_profile.parameters.base_address, base);
  const limitations = collectLimitations([opened, status, image]);
  assert.ok(
    limitations.some((text) => RX_COMMUNITY_MODULE_LIMITATION.test(text)),
    `No community-module limitation among: ${JSON.stringify(limitations)}`,
  );

  const memory = evidence(
    await call("read_bytes", { address: base, length: bytes.length }),
  );
  assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));
  for (const [offset, expected] of [
    [0x00, Buffer.from("44332211", "hex")],
    [0x10, MARKER],
    [0x30, TAIL],
  ]) {
    const read = evidence(
      await call("read_bytes", {
        address: at(offset),
        length: expected.length,
      }),
    );
    assert.equal(read.normalized_result.bytes_hex, expected.toString("hex"));
  }

  const procedures = evidence(await call("list_procedures")).normalized_result;
  assert.deepEqual(procedures.map((procedure) => procedure.address).sort(), [
    entry,
    leaf,
  ]);
  assert.equal(
    procedures.find((procedure) => procedure.address === entry)?.value,
    "entry",
    "Entry procedure is not named entry",
  );
  const instruction = evidence(
    await call("inspect_native_instruction", { address: entry }),
  ).normalized_result;
  assert.equal(instruction.mnemonic.toUpperCase(), "BSR.W");
  assert.equal(instruction.flow.kind, "call");
  assert.deepEqual(instruction.flow.direct_destinations, [leaf]);
  assert.ok(
    instruction.references.some(
      (reference) =>
        reference.call &&
        reference.type === "UNCONDITIONAL_CALL" &&
        reference.target_address === leaf,
    ),
  );
  const callees = evidence(
    await call("procedure_callees", { procedure: entry }),
  ).normalized_result;
  assert.ok(
    callees.some((callee) => BigInt(calleeAddress(callee)) === BigInt(leaf)),
    `Direct call to the leaf not recovered: ${JSON.stringify(callees)}`,
  );
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: leaf }),
  );
  assert.match(
    pseudo.normalized_result,
    /return\s+(?:0x12345678|305419896)\s*;/iu,
  );
  const caller = evidence(
    await call("procedure_pseudo_code", { procedure: entry }),
  );
  assert.match(caller.normalized_result, /\w*fff00028\s*\(\s*\)/iu);
  assert.match(caller.normalized_result, /\+\s*(?:1|0x1)\s*;/iu);
  // File offsets resolve through the base, not the entry.
  const filePseudo = evidence(
    await call("procedure_pseudo_code", {
      procedure: `file-offset:0x${LEAF_OFFSET.toString(16)}`,
    }),
  );
  assert.equal(filePseudo.normalized_result, pseudo.normalized_result);
  assert.ok(
    filePseudo.locations.some(
      (location) =>
        location.kind === "file-offset" && location.offset === LEAF_OFFSET,
    ),
  );

  // Rejected selections must not replace the live session.
  for (const [selection, reason] of [
    // One byte past the mapped image.
    [
      { base_address: base, entry_point: at(bytes.length) },
      RX_ENTRY_OUTSIDE_IMAGE,
    ],
    // The entry precedes the base.
    [{ base_address: at(1), entry_point: base }, RX_ENTRY_OUTSIDE_IMAGE],
    // 0xffffffe0 + 0x38 bytes passes 0xffffffff.
    [
      { base_address: "0xffffffe0", entry_point: "0xffffffe0" },
      RX_MAPPING_PAST_WIDTH,
    ],
  ]) {
    const rejected = await client.callTool({
      name: "open_binary",
      arguments: { ...rawSelection, ...selection },
    });
    assert.equal(rejected.isError, true, JSON.stringify(selection));
    assert.match(JSON.stringify(rejected.content), reason);
    const preserved = await call("binary_session");
    assert.equal(preserved.analysis_run.run_id, status.analysis_run.run_id);
    assert.equal(preserved.entry_point, entry);
  }
  await call("close_binary");
  await client.ping();

  const cliSelection = [
    "--target-format",
    "raw-binary",
    "--architecture",
    "rx",
    "--base-address",
    base,
    "--entry-point",
    entry,
    "--provider",
    "ghidra",
    "--json",
  ];
  const { stdout } = await exec(
    process.execPath,
    [entrypoint, "inspect-native-load-image", path, ...cliSelection],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const cli = evidence(JSON.parse(stdout));
  assert.deepEqual(cli.normalized_result, image.normalized_result);
  assert.equal(cli.analysis_profile.digest, image.analysis_profile.digest);
  const fileCli = await exec(
    process.execPath,
    [
      entrypoint,
      "decompile",
      path,
      `--file-offset=0x${LEAF_OFFSET.toString(16)}`,
      ...cliSelection,
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const fileCliEvidence = evidence(JSON.parse(fileCli.stdout));
  assert.equal(fileCliEvidence.normalized_result, filePseudo.normalized_result);
  assert.deepEqual(fileCliEvidence.locations, filePseudo.locations);
  assert.deepEqual(await readFile(path), bytes);
  assert.deepEqual(
    (await readdir(runtime)).filter((name) => name.startsWith("rea-ghidra-")),
    [],
    "Owned Ghidra runtime survived close",
  );
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-rx",
    host: process.platform,
    provider: image.provider,
    target: {
      sha256,
      bytes: bytes.length,
      architecture: "rx",
      base,
      entry,
    },
    language_id: RX_LANGUAGE,
    community_module_limitation: true,
    cli_mcp_load_image_parity: true,
    data_marker_and_tail_bytes: true,
    entry_procedure: true,
    instructions_and_call_reference: true,
    decompilation: true,
    file_offset_decompilation_cli_mcp: true,
    entry_outside_image_preserves_session: true,
    invalid_mapping_preserves_session: true,
    source_unchanged: true,
    runtime_cleanup: "complete",
  };
} catch (cause) {
  if (stderr) process.stderr.write(stderr);
  throw cause;
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
  }
}
assert.deepEqual(
  await readdir(runtime),
  [],
  `Runtime resources survived server shutdown; retained workspace: ${workspace}`,
);
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
// Keep the workspace for diagnosis unless verification and cleanup both pass.
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  if (["open_binary", "binary_session", "close_binary"].includes(name))
    return requireMcpOperationResult(result, name);
  return requireMcpOutput(result, name);
}

function evidence(value) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, sha256);
  assert.equal(result.subject.architecture, "rx");
  assert.equal(result.subject.format, "raw-binary");
  return result;
}

/** Every string under any `limitations` key, wherever the producer reports it. */
function collectLimitations(values) {
  const found = [];
  const visit = (value, inLimitations) => {
    if (typeof value === "string") {
      if (inLimitations) found.push(value);
    } else if (Array.isArray(value)) {
      for (const item of value) visit(item, inLimitations);
    } else if (value !== null && typeof value === "object") {
      for (const [key, item] of Object.entries(value))
        visit(item, inLimitations || key === "limitations");
    }
  };
  visit(values, false);
  return found;
}

function calleeAddress(callee) {
  return typeof callee === "string" ? callee : callee.address;
}
