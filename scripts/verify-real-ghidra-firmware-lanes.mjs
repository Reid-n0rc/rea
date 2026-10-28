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

// Verifies the raw-binary firmware lanes armv8m (ARM:LE:32:v8-m, Thumb),
// xtensa (stock Xtensa:LE:32:default) and xtensa-hifi4 (the caller-installed
// Xtensa:LE:32:rt600hifi4 language) against real Ghidra. Usage:
//   node scripts/verify-real-ghidra-firmware-lanes.mjs [armv8m|xtensa|xtensa-hifi4|armv8m-readonly ...]
// armv8m-readonly checks REA_GHIDRA_RAW_READONLY_RANGES (split, non-writable pieces, folded loads).
// A lane whose language is not in the installation catalog prints a skipped:
// line; refusal of an absent language is covered by source tests.
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "Firmware raw-binary verification requires a Linux or macOS Ghidra host.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );

// Source-owned little-endian images. Each starts with a 16-byte word table and
// a 16-byte ASCII marker, so the entry (offset 0x20) differs from the base.
const WORDS = Buffer.from("4433221188776655ccbbaa9900ffeedd", "hex");
const TAIL = Buffer.from("5441494cefbeadde", "hex"); // "TAIL" 0xdeadbeef
const marker = (text) => Buffer.from(text.padEnd(16, "\0"), "latin1");
// Thumb-2 (hand-encoded, checked with Ghidra's ARM:LE:32:v8-m):
//   +0x20 10b5      push {r4, lr}               entry
//   +0x22 00f003f8  bl   leaf (+0x2c)
//   +0x26 0130      adds r0, #1
//   +0x28 10bd      pop  {r4, pc}
//   +0x2a 00bf      nop
//   +0x2c 2a20      movs r0, #0x2a              leaf
//   +0x2e 7047      bx   lr
//   +0x30 78563412  .word 0x12345678
//   +0x34 "TAIL" efbeadde
const THUMB = Buffer.concat([
  WORDS,
  marker("REA-V8M-FIXTURE"),
  Buffer.from("10b500f003f8013010bd00bf2a20704778563412", "hex"),
  TAIL,
]);
// Xtensa call0 ABI, assembled with the Zephyr SDK 0.17.0
// xtensa-nxp_rt600_adsp_zephyr-elf-as (no-transform, no density ops), so the
// stock and the RT600 HiFi4 languages decode the same bytes:
//   +0x20 12c1f0  addi  a1, a1, -16              entry
//   +0x23 026100  s32i  a0, a1, 0
//   +0x26 050100  call0 leaf (+0x38)
//   +0x29 22c201  addi  a2, a2, 1
//   +0x2c 022100  l32i  a0, a1, 0
//   +0x2f 12c110  addi  a1, a1, 16
//   +0x32 800000  ret
//   +0x35 000000  (padding)
//   +0x38 22a5a5  movi  a2, 0x5a5                leaf
//   +0x3b 800000  ret
//   +0x3e 0000    (padding)
//   +0x40 "TAIL" efbeadde
const XTENSA = Buffer.concat([
  WORDS,
  marker("REA-XT-FIXTURE"),
  Buffer.from(
    "12c1f0026100050100" +
      "22c201022100" +
      "12c110800000000000" +
      "22a5a58000000000",
    "hex",
  ),
  TAIL,
]);

// Read-only ranges (REA_GHIDRA_RAW_READONLY_RANGES), hand-encoded Thumb:
//   +0x00 word table (first word 0x11223344) and marker   read-only
//   +0x20 0148      ldr  r0, [pc, #4]  (literal +0x28)   entry
//   +0x22 0068      ldr  r0, [r0]
//   +0x24 7047      bx   lr
//   +0x26 00bf      nop
//   +0x28 00000008  .word 0x08000000 (the table)          read-only
//   +0x2c "TAIL" efbeadde
// The decompiler folds both loads to the table's first word only when the
// literal and the table are not writable.
const READONLY_THUMB = Buffer.concat([
  WORDS,
  marker("REA-V8M-RO"),
  Buffer.from("01480068704700bf00000008", "hex"),
  TAIL,
]);

const LANES = {
  armv8m: {
    language: "ARM:LE:32:v8-m",
    bytes: THUMB,
    base: 0x08000000n,
    entryOffset: 0x20,
    leafOffset: 0x2c,
    entryMnemonic: /^push$/iu,
    leafReturn: /return\s+(?:0x2a|42)\s*;/iu,
    tailOffset: 0x34,
    limitation: null,
  },
  xtensa: {
    language: "Xtensa:LE:32:default",
    bytes: XTENSA,
    base: 0x40000n,
    entryOffset: 0x20,
    leafOffset: 0x38,
    entryMnemonic: /^addi$/iu,
    leafReturn: /return\s+(?:0x5a5|1445)\s*;/iu,
    tailOffset: 0x40,
    limitation: null,
  },
  "xtensa-hifi4": {
    language: "Xtensa:LE:32:rt600hifi4",
    bytes: XTENSA,
    base: 0x00200000n,
    entryOffset: 0x20,
    leafOffset: 0x38,
    entryMnemonic: /^addi$/iu,
    leafReturn: /return\s+(?:0x5a5|1445)\s*;/iu,
    tailOffset: 0x40,
    limitation:
      /Xtensa:LE:32:rt600hifi4 comes from the community Xtensa RT600 HiFi4 \(generated\) processor module [^]*it is not shipped with Ghidra/u,
  },
};
LANES["armv8m-readonly"] = {
  architecture: "armv8m",
  language: "ARM:LE:32:v8-m",
  bytes: READONLY_THUMB,
  base: 0x08000000n,
  entryOffset: 0x20,
  tailOffset: 0x2c,
  readonlyRanges: "0x8000000-0x800001f,0x8000028-0x800002b",
  // read-only pieces, then writable pieces, in address order
  pieces: [true, false, true, false],
  folded: /return\s+0x11223344\s*;/iu,
};
for (const lane of Object.values(LANES))
  assert.deepEqual(lane.bytes.subarray(lane.tailOffset), TAIL);

const selected = process.argv.slice(2);
for (const name of selected)
  if (!(name in LANES)) throw new Error(`Unknown lane ${name}`);
const laneNames = selected.length === 0 ? Object.keys(LANES) : selected;

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
const languageScope = new ArtifactResourceScope();
let catalog;
try {
  catalog = await readGhidraLanguageCatalog(
    installation.installDir,
    languageScope,
  );
} finally {
  await languageScope.close();
}

const exec = promisify(execFile);
const root = fileURLToPath(new URL("..", import.meta.url));
const entrypoint = join(root, "scripts", "rea.mjs");
const reports = [];
for (const name of laneNames) {
  const lane = LANES[name];
  if (!catalog.some((definition) => definition.id === lane.language)) {
    process.stdout.write(
      `skipped: ${name} ${lane.language} (not in the Ghidra installation catalog that REA admits)\n`,
    );
    continue;
  }
  reports.push(
    await (lane.readonlyRanges === undefined
      ? verifyLane(name, lane)
      : verifyReadonlyLane(name, lane)),
  );
}
process.stdout.write(JSON.stringify({ ok: true, lanes: reports }) + "\n");

async function verifyLane(architecture, lane) {
  const { bytes } = lane;
  const run = createVerifierRun();
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const at = (offset) => `0x${(lane.base + BigInt(offset)).toString(16)}`;
  const base = at(0);
  const entry = at(lane.entryOffset);
  const leaf = at(lane.leafOffset);
  const { workspace, runtime, path } = await makeWorkspace(architecture, bytes);
  const env = laneEnvironment(runtime, run);
  const { client, transport, call, stderr } = mcpLaneClient(architecture, env);
  const evidence = evidenceChecker(sha256, architecture);
  let report;
  try {
    await client.connect(transport);
    const { image, loaded, addresses, pseudo } = await checkMcpLane(
      call,
      evidence,
      lane,
      { path, architecture, base, entry, leaf },
    );
    await call("close_binary");
    await client.ping();

    const stdout = await cliDecompile(env, lane, {
      path,
      architecture,
      base,
      entry,
    });
    const cli = evidence(JSON.parse(stdout));
    assert.equal(cli.normalized_result, pseudo.normalized_result);
    assert.deepEqual(await readFile(path), bytes);
    report = {
      lane: `ghidra-${architecture}`,
      mocked: false,
      host: process.platform,
      provider: image.provider,
      target: { sha256, bytes: bytes.length, architecture, base, entry },
      language_id: lane.language,
      load_image: loaded.status,
      procedures: addresses.length,
      call_reference: true,
      decompilation: true,
      cli_mcp_decompilation_parity: true,
      source_unchanged: true,
    };
  } catch (cause) {
    if (stderr()) process.stderr.write(stderr());
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
  await rm(workspace, { recursive: true, force: true });
  return { verifier_run: verifierRun.process_lineage.status, ...report };
}

/**
 * Opens the read-only fixture through MCP with REA_GHIDRA_RAW_READONLY_RANGES,
 * checks the verified split load image and the folded pseudocode, and checks
 * through the CLI that the same import without the ranges does not fold.
 */
async function verifyReadonlyLane(name, lane) {
  const { bytes, architecture } = lane;
  const run = createVerifierRun();
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const at = (offset) => `0x${(lane.base + BigInt(offset)).toString(16)}`;
  const base = at(0);
  const entry = at(lane.entryOffset);
  const { workspace, runtime, path } = await makeWorkspace(name, bytes);
  const plainEnv = laneEnvironment(runtime, run);
  delete plainEnv.REA_GHIDRA_RAW_READONLY_RANGES;
  const env = {
    ...plainEnv,
    REA_GHIDRA_RAW_READONLY_RANGES: lane.readonlyRanges,
  };
  const evidence = evidenceChecker(sha256, architecture);
  const { client, transport, call, stderr } = mcpLaneClient(name, env);
  let report;
  try {
    await client.connect(transport);
    await call("open_binary", {
      path,
      format: "raw-binary",
      architecture,
      base_address: base,
      entry_point: entry,
      provider_id: "ghidra",
    });
    const image = evidence(await call("inspect_native_load_image"));
    const loaded = image.normalized_result;
    assert.equal(loaded.status, "verified", JSON.stringify(loaded));
    assert.deepEqual(
      image.analysis_profile.parameters.readonly_ranges,
      lane.readonlyRanges.split(","),
    );
    const mappings = loaded.observations.mappings.filter(
      (mapping) => mapping.source_file_index !== null,
    );
    assert.deepEqual(
      mappings.map((mapping) => !mapping.writable),
      lane.pieces,
    );
    assert.ok(
      loaded.limitations.some((text) =>
        text.includes("REA_GHIDRA_RAW_READONLY_RANGES split the file"),
      ),
    );
    const pseudo = evidence(
      await call("procedure_pseudo_code", { procedure: entry }),
    );
    assert.match(pseudo.normalized_result, lane.folded);
    await call("close_binary");

    const decompileEntry = (environment) =>
      cliDecompile(environment, lane, {
        path,
        architecture,
        base,
        entry,
        fileOffset: lane.entryOffset,
      });
    const ranged = evidence(JSON.parse(await decompileEntry(env)));
    assert.equal(ranged.normalized_result, pseudo.normalized_result);
    const plain = evidence(JSON.parse(await decompileEntry(plainEnv)));
    assert.doesNotMatch(plain.normalized_result, lane.folded);
    assert.deepEqual(await readFile(path), bytes);
    report = {
      lane: `ghidra-${name}`,
      mocked: false,
      host: process.platform,
      provider: image.provider,
      target: { sha256, bytes: bytes.length, architecture, base, entry },
      readonly_ranges: lane.readonlyRanges,
      load_image: loaded.status,
      file_mappings: mappings.length,
      folded_with_ranges: true,
      folded_without_ranges: false,
      cli_mcp_decompilation_parity: true,
      source_unchanged: true,
    };
  } catch (cause) {
    if (stderr()) process.stderr.write(stderr());
    throw cause;
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  assert.deepEqual(await readdir(runtime), []);
  const verifierRun = await completeVerifierRun(run);
  assert.equal(verifierRun.process_lineage.status, "verified");
  await rm(workspace, { recursive: true, force: true });
  return { verifier_run: verifierRun.process_lineage.status, ...report };
}

/** Server and CLI environment confined to the lane's runtime directory. */
function laneEnvironment(runtime, run) {
  return {
    ...process.env,
    TMPDIR: runtime,
    TMP: runtime,
    TEMP: runtime,
    REA_LOG_LEVEL: "silent",
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_PROCESS_RUN_ID: run.run_id,
  };
}

/** A stdio MCP client for one lane; `call` unwraps operation and output results. */
function mcpLaneClient(name, env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: `rea-real-${name}-proof`, version: "1" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const call = async (tool, args = {}) => {
    const result = await client.callTool(
      { name: tool, arguments: args },
      { timeout: 240000 },
    );
    if (["open_binary", "binary_session", "close_binary"].includes(tool))
      return requireMcpOperationResult(result, tool);
    return requireMcpOutput(result, tool);
  };
  return { client, transport, call, stderr: () => stderr };
}

/** Parses Evidence and checks it names the fixture as a raw-binary target. */
function evidenceChecker(sha256, architecture) {
  return (value) => {
    const result = parseEvidence(value);
    assert.equal(result.subject.digest.sha256, sha256);
    assert.equal(result.subject.architecture, architecture);
    assert.equal(result.subject.format, "raw-binary");
    return result;
  };
}

/** A private build/ workspace holding the fixture and an empty runtime directory. */
async function makeWorkspace(architecture, bytes) {
  await mkdir(join(root, "build"), { recursive: true });
  const workspace = await mkdtemp(
    join(root, "build", `rea-${architecture}-proof-`),
  );
  const runtime = join(workspace, "runtime");
  await mkdir(runtime);
  const path = join(workspace, "image.bin");
  await writeFile(path, bytes);
  return { workspace, runtime, path };
}

/** MCP checks for one opened lane; returns what the report and CLI parity need. */
async function checkMcpLane(call, evidence, lane, target) {
  const { path, architecture, base, entry, leaf } = target;
  const { bytes } = lane;
  const opened = await call("open_binary", {
    path,
    format: "raw-binary",
    architecture,
    base_address: base.toUpperCase().replace("0X", "0x"),
    entry_point: entry,
    provider_id: "ghidra",
  });
  assert.equal(opened.architecture, architecture);
  assert.equal(opened.entry_point, entry);
  assert.equal(opened.base_address, base);
  const status = await call("binary_session");
  const image = evidence(await call("inspect_native_load_image"));
  const loaded = image.normalized_result;
  assert.equal(loaded.status, "verified", JSON.stringify(loaded));
  assert.equal(loaded.base_address, base);
  assert.equal(loaded.entry.address, entry);
  assert.equal(loaded.entry.file_offset, lane.entryOffset);
  assert.equal(loaded.language_id, lane.language);
  assert.equal(loaded.compiler_spec_id, "default");
  assert.equal(loaded.file_bytes, bytes.length);
  assert.equal(image.analysis_profile.parameters.language_id, lane.language);
  const limitations = collectLimitations([opened, status, image]);
  if (lane.limitation !== null)
    assert.ok(
      limitations.some((text) => lane.limitation.test(text)),
      `No language limitation among: ${JSON.stringify(limitations)}`,
    );
  const memory = evidence(
    await call("read_bytes", { address: base, length: bytes.length }),
  );
  assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));

  const procedures = evidence(await call("list_procedures")).normalized_result;
  const addresses = procedures.map((procedure) => procedure.address);
  assert.ok(addresses.includes(entry), JSON.stringify(procedures));
  assert.ok(addresses.includes(leaf), JSON.stringify(procedures));
  const instruction = evidence(
    await call("inspect_native_instruction", { address: entry }),
  ).normalized_result;
  assert.match(instruction.mnemonic, lane.entryMnemonic);
  const callees = evidence(
    await call("procedure_callees", { procedure: entry }),
  ).normalized_result;
  assert.ok(
    callees.some(
      (callee) =>
        BigInt(typeof callee === "string" ? callee : callee.address) ===
        BigInt(leaf),
    ),
    `Direct call to the leaf not recovered: ${JSON.stringify(callees)}`,
  );
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: leaf }),
  );
  assert.match(pseudo.normalized_result, lane.leafReturn);
  const caller = evidence(
    await call("procedure_pseudo_code", { procedure: entry }),
  );
  assert.match(
    caller.normalized_result,
    new RegExp(`\\w*${leaf.slice(2)}\\s*\\(`, "iu"),
  );
  // Thumb disassembly must not have fallen back to ARM mode.
  assert.doesNotMatch(caller.normalized_result, /halt_baddata/u);
  return { image, loaded, addresses, pseudo };
}

/** Decompiles the leaf through the compiled CLI and returns its stdout. */
async function cliDecompile(env, lane, target) {
  const { path, architecture, base, entry } = target;
  const fileOffset = target.fileOffset ?? lane.leafOffset;
  const { stdout } = await exec(
    process.execPath,
    [
      entrypoint,
      "decompile",
      path,
      `--file-offset=0x${fileOffset.toString(16)}`,
      "--target-format",
      "raw-binary",
      "--architecture",
      architecture,
      "--base-address",
      base,
      "--entry-point",
      entry,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  return stdout;
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
