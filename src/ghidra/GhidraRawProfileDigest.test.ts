import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

// Digests were computed by the unmodified upstream resolver (3ae7daa10,
// raw branch inline) and must not change when the binary-loader policy is shared.
const RAW_DIGESTS = {
  "6502": "adbec31711f31471f9cdbdbb2fc743a0ce6b46c9be5568bf90a3f51ef46e376d",
  "x86-disabled-analyzer":
    "493a02888eca575be286b5a96041af8007444586854edb974d6a0c12fd2768c4",
} as const;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (
  architecture: "6502" | "x86",
  entryPoint: string,
  baseAddress?: string,
): BinaryTarget =>
  ({
    path: "/tmp/raw.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
    ...(baseAddress === undefined
      ? {}
      : { baseAddress, baseAddressSource: baseAddress }),
  }) as unknown as BinaryTarget;

describe("raw-binary analysis profile digest", () => {
  it("keeps the 6502 raw profile digest from before the shared policy refactor", async () => {
    const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const resolved = await ghidra.resolveAnalysisProfile(raw("6502", "0x8001"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(RAW_DIGESTS["6502"]);
    expect(resolved.value.profile?.parameters).toMatchObject({
      target_format: "raw-binary",
      loader: "BinaryLoader",
      language_id: "6502:LE:16:default",
      language_selection: "caller-supplied-v1",
      load_image_evidence: "independent-raw-mapping-context-v4",
      analyzer_preset: "ghidra-default",
    });
  });

  it("keeps the disabled-analyzer raw digest and its analysis options", async () => {
    const ghidra = new GhidraProvider(
      configFor({
        REA_GHIDRA_DISABLED_ANALYZERS: "Aggressive Instruction Finder",
      }),
      silentLogger,
      {},
      host,
    );
    const resolved = await ghidra.resolveAnalysisProfile(raw("x86", "0x1000"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(
      RAW_DIGESTS["x86-disabled-analyzer"],
    );
    expect(resolved.value.profile?.parameters).toMatchObject({
      analysis_options: {
        disabled_analyzers: ["Aggressive Instruction Finder"],
      },
    });
  });

  it("keeps the profile without base_address and commits a separate base", async () => {
    const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const plain = await ghidra.resolveAnalysisProfile(raw("6502", "0x8001"));
    const based = await ghidra.resolveAnalysisProfile(
      raw("6502", "0x8001", "0x8000"),
    );
    const moved = await ghidra.resolveAnalysisProfile(
      raw("6502", "0x8001", "0x7000"),
    );
    if (!plain.ok || !based.ok || !moved.ok)
      throw new Error("expected raw profiles");
    expect(plain.value.profile?.digest).toBe(RAW_DIGESTS["6502"]);
    expect(plain.value.profile?.parameters).not.toHaveProperty("base_address");
    expect(based.value.profile?.parameters).toMatchObject({
      entry_point: "0x8001",
      base_address: "0x8000",
    });
    const digests = new Set([
      plain.value.profile?.digest,
      based.value.profile?.digest,
      moved.value.profile?.digest,
    ]);
    expect(digests.size).toBe(3);
    // Function coordinates depend on where file offset 0 is mapped.
    expect(
      based.value.profile?.parameters.function_coordinate_context,
    ).not.toEqual(plain.value.profile?.parameters.function_coordinate_context);
  });

  it("commits REA_GHIDRA_RAW_READONLY_RANGES inside the image and refuses ranges outside it", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-raw-readonly-"));
    try {
      const path = join(directory, "dsp.bin");
      await writeFile(path, Buffer.alloc(0x100));
      const target = {
        ...raw("x86", "0x1080", "0x1000"),
        path,
      } as BinaryTarget;
      const plain = await new GhidraProvider(
        configFor({}),
        silentLogger,
        {},
        host,
      ).resolveAnalysisProfile(target);
      const ranged = await new GhidraProvider(
        configFor({
          REA_GHIDRA_RAW_READONLY_RANGES: "0x10C0-0x10ff, 0x1000-0x103F",
        }),
        silentLogger,
        {},
        host,
      ).resolveAnalysisProfile(target);
      if (!plain.ok || !ranged.ok) throw new Error("expected raw profiles");
      expect(plain.value.profile?.parameters).not.toHaveProperty(
        "readonly_ranges",
      );
      expect(ranged.value.profile?.parameters).toMatchObject({
        base_address: "0x1000",
        readonly_ranges: ["0x1000-0x103f", "0x10c0-0x10ff"],
      });
      expect(ranged.value.profile?.digest).not.toBe(
        plain.value.profile?.digest,
      );

      const outside = await new GhidraProvider(
        configFor({ REA_GHIDRA_RAW_READONLY_RANGES: "0x10f0-0x1100" }),
        silentLogger,
        {},
        host,
      ).resolveAnalysisProfile(target);
      expect(outside.ok).toBe(false);
      if (outside.ok) return;
      expect(outside.error.message).toContain(
        "0x10f0-0x1100 must lie inside the mapped raw-binary image 0x1000-0x10ff",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
