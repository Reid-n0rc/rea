import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { attestGhidraRawBinaryLoadImage } from "./GhidraLoadImageValues.js";
import { fixtureRawBinaryLoadImage } from "./GhidraRawBinaryLoadImage.fixture.js";
import {
  ghidraRawBinaryLanguage,
  ghidraRawBinaryLanguageLimitations,
} from "./GhidraRawBinaryLanguage.js";

const RAW_LOAD_IMAGE_WITHOUT_BASE_SHA256 =
  "22e87550552b7d26eb5547161f6d7b815ceab8e158642058ee4796bc3848f948";

describe("raw-binary Ghidra language binding", () => {
  it("maps the big-endian m68k family to the default 68000 language", () => {
    expect(ghidraRawBinaryLanguage("m68k")).toEqual({
      languageId: "68000:BE:32:default",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    });
  });
  it("maps rx to the community rx62t language and owes its limitation", () => {
    const language = ghidraRawBinaryLanguage("rx");
    expect(language).toEqual({
      languageId: "rx62t:LE:32:default",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
      communityModule: {
        name: "RX",
        source: "github.com/stefan00lpf/rx-proc-ghidra",
      },
    });
    expect(ghidraRawBinaryLanguageLimitations(language)).toEqual([
      expect.stringMatching(
        /^rx62t:LE:32:default comes from the community RX processor module .* not shipped with Ghidra\. REA has not established its instruction decoding/u,
      ),
    ]);
    for (const architecture of [
      "x86",
      "x86_64",
      "arm",
      "arm64",
      "6502",
      "m68k",
      "armv8m",
      "xtensa",
    ] as const)
      expect(
        ghidraRawBinaryLanguageLimitations(
          ghidraRawBinaryLanguage(architecture),
        ),
      ).toEqual([]);
  });
  it("maps armv8m to Ghidra's Thumb-only ARMv8-M language and xtensa to the stock Xtensa language", () => {
    expect(ghidraRawBinaryLanguage("armv8m")).toEqual({
      languageId: "ARM:LE:32:v8-m",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    });
    expect(ghidraRawBinaryLanguage("xtensa")).toEqual({
      languageId: "Xtensa:LE:32:default",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    });
  });
  it("maps xtensa-hifi4 to the generated RT600 HiFi4 language and owes its limitation", () => {
    const language = ghidraRawBinaryLanguage("xtensa-hifi4");
    expect(language).toEqual({
      languageId: "Xtensa:LE:32:rt600hifi4",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
      communityModule: {
        name: "Xtensa RT600 HiFi4 (generated)",
        source:
          "github.com/Reid-n0rc/FT-710_Firmware tools/xtensa_sleigh_gen.py",
      },
    });
    expect(ghidraRawBinaryLanguageLimitations(language)).toEqual([
      expect.stringMatching(
        /^Xtensa:LE:32:rt600hifi4 comes from the community Xtensa RT600 HiFi4 \(generated\) processor module .* not shipped with Ghidra\./u,
      ),
    ]);
  });
  it("maps the four admitted families to little-endian generic languages", () => {
    expect(ghidraRawBinaryLanguage("x86")).toEqual({
      languageId: "x86:LE:32:default",
      compilerSpecId: "gcc",
      defaultAddressSpace: "ram",
    });
    expect(ghidraRawBinaryLanguage("x86_64")).toEqual({
      languageId: "x86:LE:64:default",
      compilerSpecId: "gcc",
      defaultAddressSpace: "ram",
    });
    expect(ghidraRawBinaryLanguage("arm")).toEqual({
      languageId: "ARM:LE:32:v7",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    });
    expect(ghidraRawBinaryLanguage("arm64")).toEqual({
      languageId: "AARCH64:LE:64:v8A",
      compilerSpecId: "default",
      defaultAddressSpace: "ram",
    });
  });
});

describe("raw-binary mapped-block state", () => {
  it.each(["RAM", "ram"])(
    "requires the bound 6502 address space for %s observations",
    (space) => {
      const f = fixtureRawBinaryLoadImage();
      const target = {
        ...f.target,
        architecture: "6502" as const,
        availableArchitectures: ["6502" as const],
        entryPoint: "0x8001",
        entryPointSource: "0x8001",
      };
      f.observation.language_id = "6502:LE:16:default";
      f.observation.default_address_space = space;
      f.observation.entry_points = [target.entryPoint];
      const mapping = f.observation.mappings[0];
      if (mapping === undefined)
        throw new Error("Missing source mapping fixture");
      mapping.start = target.entryPoint;
      mapping.end = "0x8004";
      mapping.address_space = space;
      expect(
        attestGhidraRawBinaryLoadImage(f.snapshot, target, f.observation),
      ).toMatchObject({
        ok: true,
        value: {
          status: space === "RAM" ? "verified" : "mismatch",
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: "default_address_space",
              expected: "RAM",
              observed: space,
              matched: space === "RAM",
            }),
          ]),
        },
      });
    },
  );
  it.each(["ram", "RAM"])(
    "requires the bound m68k address space for %s observations",
    (space) => {
      const f = fixtureRawBinaryLoadImage();
      const target = {
        ...f.target,
        architecture: "m68k" as const,
        availableArchitectures: ["m68k" as const],
        entryPoint: "0x1000",
        entryPointSource: "0x1000",
      };
      f.observation.language_id = "68000:BE:32:default";
      f.observation.default_address_space = space;
      f.observation.entry_points = [target.entryPoint];
      const mapping = f.observation.mappings[0];
      if (mapping === undefined)
        throw new Error("Missing source mapping fixture");
      mapping.start = target.entryPoint;
      mapping.end = "0x1003";
      mapping.address_space = space;
      expect(
        attestGhidraRawBinaryLoadImage(f.snapshot, target, f.observation),
      ).toMatchObject({
        ok: true,
        value: {
          status: space === "ram" ? "verified" : "mismatch",
          language_id: "68000:BE:32:default",
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: "default_address_space",
              expected: "ram",
              observed: space,
              matched: space === "ram",
            }),
          ]),
        },
      });
    },
  );
  it.each([
    ["initialized", false],
    ["loaded", false],
    ["overlay", true],
    ["address_space", "overlay"],
  ] as const)(
    "retains a mismatch when the file mapping declares %s=%s",
    (property, value) => {
      const f = fixtureRawBinaryLoadImage();
      const mapping = f.observation.mappings[0];
      if (mapping === undefined)
        throw new Error("Missing source mapping fixture");
      Object.assign(mapping, { [property]: value });
      expect(
        attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
      ).toMatchObject({
        ok: true,
        value: {
          status: "mismatch",
          observations: f.observation,
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: `mapping.${property}`,
              matched: false,
              observed: value,
            }),
          ]),
        },
      });
    },
  );
  it("does not verify a foreign default address space even when its mapping agrees", () => {
    const f = fixtureRawBinaryLoadImage();
    f.observation.default_address_space = "foreign";
    const mapping = f.observation.mappings[0];
    if (mapping === undefined)
      throw new Error("Missing source mapping fixture");
    mapping.address_space = "foreign";
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: {
        status: "mismatch",
        observations: f.observation,
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "default_address_space",
            matched: false,
            observed: "foreign",
          }),
        ]),
      },
    });
  });
});

describe("raw-binary independent load-image checks", () => {
  it("retains uninitialized language memory without treating it as file-backed bytes", () => {
    const f = fixtureRawBinaryLoadImage();
    const zeroPage = {
      block: "ZERO_PAGE",
      start: "0x0",
      end: "0xff",
      address_space: "ram",
      initialized: false,
      loaded: true,
      overlay: false,
      readable: true,
      writable: true,
      executable: false,
      length: 256,
      source_file_index: null,
      file_offset: null,
      sha256: null,
    };
    f.observation.mappings.unshift(zeroPage);
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: { status: "verified", observations: f.observation },
    });
    zeroPage.initialized = true;
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: {
        status: "mismatch",
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "initialized_unbacked_mappings",
            matched: false,
          }),
        ]),
      },
    });
  });
  it("verifies mapped bytes at the caller-supplied entry", () => {
    const f = fixtureRawBinaryLoadImage();
    const result = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      f.target,
      f.observation,
    );
    expect(result).toMatchObject({
      ok: true,
      value: {
        status: "verified",
        format: "raw-binary",
        architecture: "arm",
        language_id: "ARM:LE:32:v7",
        base_address: "0x8000000",
        file_bytes: 4,
        entry: { address: "0x8000000", file_offset: 0 },
      },
    });
  });
  it("retains mismatch evidence for a drifted language", () => {
    const f = fixtureRawBinaryLoadImage();
    f.observation.language_id = "x86:LE:32:default";
    const result = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      f.target,
      f.observation,
    );
    expect(result).toMatchObject({
      ok: true,
      value: { status: "mismatch", observations: f.observation },
    });
  });
  it("preserves additional language entries while requiring the caller entry", () => {
    const f = fixtureRawBinaryLoadImage();
    f.observation.entry_points = ["0x0", f.target.entryPoint, "0xffff0000"];
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: { status: "verified", observations: f.observation },
    });
    f.observation.entry_points = ["0x0", "0xffff0000"];
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: {
        status: "mismatch",
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "entry_point",
            matched: false,
            observed: null,
          }),
        ]),
      },
    });
  });
  it("keeps the load image of a target without base_address byte-for-byte", () => {
    // Digest of the complete attestation produced before base_address existed.
    const f = fixtureRawBinaryLoadImage();
    const result = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      f.target,
      f.observation,
    );
    if (!result.ok) throw new Error(result.error);
    expect(
      createHash("sha256").update(JSON.stringify(result.value)).digest("hex"),
    ).toBe(RAW_LOAD_IMAGE_WITHOUT_BASE_SHA256);
    expect(JSON.stringify(result.value)).not.toContain(
      "entry_point.file_offset",
    );
  });
  it("rejects stale snapshot identity", () => {
    const f = fixtureRawBinaryLoadImage();
    expect(
      attestGhidraRawBinaryLoadImage(
        f.snapshot,
        { ...f.target, sha256: "f".repeat(64) },
        f.observation,
      ).ok,
    ).toBe(false);
  });
});

describe("raw-binary community language attestation", () => {
  it("verifies an odd-entry rx load image and reports the community language limitation", () => {
    const f = fixtureRawBinaryLoadImage();
    const target = {
      ...f.target,
      architecture: "rx" as const,
      availableArchitectures: ["rx" as const],
      entryPoint: "0x1001",
      entryPointSource: "0x1001",
    };
    f.observation.language_id = "rx62t:LE:32:default";
    f.observation.compiler_spec_id = "default";
    f.observation.default_address_space = "ram";
    f.observation.entry_points = [target.entryPoint];
    const mapping = f.observation.mappings[0];
    if (mapping === undefined)
      throw new Error("Missing source mapping fixture");
    mapping.start = target.entryPoint;
    mapping.end = "0x1004";
    mapping.address_space = "ram";
    const attested = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      target,
      f.observation,
    );
    if (!attested.ok) throw new Error(attested.error);
    expect(attested.value).toMatchObject({
      status: "verified",
      architecture: "rx",
      language_id: "rx62t:LE:32:default",
      compiler_spec_id: "default",
      base_address: "0x1001",
    });
    expect(attested.value.limitations).toEqual(
      expect.arrayContaining([
        ...ghidraRawBinaryLanguageLimitations(ghidraRawBinaryLanguage("rx")),
      ]),
    );
  });
});

describe("raw-binary load images with a separate base address", () => {
  // 8 bytes at 0x8000000: a data word, then `bx lr` at the entry 0x8000004.
  const separateBase = () => {
    const bytes = Buffer.from("efbeadde1eff2fe1", "hex");
    const digest = createHash("sha256").update(bytes).digest("hex");
    const f = fixtureRawBinaryLoadImage();
    const target = {
      ...f.target,
      sha256: digest,
      entryPoint: "0x8000004",
      entryPointSource: "0x08000004",
      baseAddress: "0x8000000",
      baseAddressSource: "0x08000000",
    };
    f.observation.entry_points = [target.entryPoint];
    const source = f.observation.source_files[0];
    const mapping = f.observation.mappings[0];
    if (source === undefined || mapping === undefined)
      throw new Error("Missing source mapping fixture");
    Object.assign(source, {
      size: bytes.length,
      original_sha256: digest,
      modified_sha256: digest,
    });
    Object.assign(mapping, {
      end: "0x8000007",
      length: bytes.length,
      sha256: digest,
    });
    return {
      snapshot: { sha256: digest, bytes: bytes.length },
      target,
      observation: f.observation,
      mapping,
    };
  };

  it("verifies file offset 0 at the base and the entry inside the mapping", () => {
    const f = separateBase();
    const result = attestGhidraRawBinaryLoadImage(
      f.snapshot,
      f.target,
      f.observation,
    );
    expect(result).toMatchObject({
      ok: true,
      value: {
        status: "verified",
        base_address: "0x8000000",
        file_bytes: 8,
        entry: { address: "0x8000004", file_offset: 4 },
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "mapping.start",
            expected: "0x8000000",
            matched: true,
          }),
          expect.objectContaining({
            name: "entry_point.file_offset",
            expected: 4,
            observed: 4,
            matched: true,
          }),
        ]),
      },
    });
    if (!result.ok) throw new Error(result.error);
    expect(result.value.limitations[1]).toContain(
      "File offset 0 is mapped at the caller-supplied base address 0x8000000; the entry is at file offset 4.",
    );
  });

  it("reports a mismatch when Ghidra mapped file offset 0 at the entry instead", () => {
    const f = separateBase();
    Object.assign(f.mapping, { start: "0x8000004", end: "0x800000b" });
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: {
        status: "mismatch",
        checks: expect.arrayContaining([
          expect.objectContaining({ name: "mapping.start", matched: false }),
          expect.objectContaining({
            name: "entry_point.file_offset",
            expected: 4,
            observed: 0,
            matched: false,
          }),
        ]),
      },
    });
  });

  it("reports an entry outside the observed file mapping as unmapped", () => {
    const f = separateBase();
    Object.assign(f.mapping, { end: "0x8000003", length: 4 });
    expect(
      attestGhidraRawBinaryLoadImage(f.snapshot, f.target, f.observation),
    ).toMatchObject({
      ok: true,
      value: {
        status: "mismatch",
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "entry_point.file_offset",
            observed: null,
            matched: false,
          }),
        ]),
      },
    });
  });
});

describe("raw-binary load images with read-only ranges", () => {
  const sha = (bytes: Buffer) =>
    createHash("sha256").update(bytes).digest("hex");
  const split = () => {
    const fixture = fixtureRawBinaryLoadImage();
    const bytes = Buffer.from("1eff2fe1", "hex");
    const [mapping] = fixture.observation.mappings;
    if (mapping === undefined) throw new Error("fixture mapping");
    const head = bytes.subarray(0, 2);
    const tail = bytes.subarray(2);
    return {
      ...fixture,
      snapshot: { ...fixture.snapshot, rangeSha256: [sha(head), sha(tail)] },
      observation: {
        ...fixture.observation,
        mappings: [
          {
            ...mapping,
            end: "0x8000001",
            length: 2,
            writable: false,
            sha256: sha(head),
          },
          {
            ...mapping,
            block: "ram.split",
            start: "0x8000002",
            end: "0x8000003",
            length: 2,
            file_offset: 2,
            writable: true,
            sha256: sha(tail),
          },
        ],
      },
    };
  };

  it("verifies the contiguous pieces, their digests and the read-only permission", () => {
    const { snapshot, target, observation } = split();
    const result = attestGhidraRawBinaryLoadImage(
      snapshot,
      target,
      observation,
      ["0x8000000-0x8000001"],
    );
    if (!result.ok) throw new Error(result.error);
    expect(result.value.status).toBe("verified");
    if (result.value.status === "unsupported") throw new Error("unsupported");
    expect(result.value.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "mapping_count", expected: 2 }),
        expect.objectContaining({
          name: "mapping[0].writable",
          expected: false,
          matched: true,
        }),
        expect.objectContaining({
          name: "mapping[1].file_offset",
          expected: 2,
          matched: true,
        }),
      ]),
    );
    expect(result.value.limitations).toContainEqual(
      expect.stringContaining(
        "split the file into 2 contiguous mappings; 0x8000000-0x8000001 is mapped read-only",
      ),
    );
  });

  it("reports a mismatch when the committed read-only piece stayed writable", () => {
    const { snapshot, target, observation } = split();
    const [first, second] = observation.mappings;
    if (first === undefined || second === undefined) throw new Error("split");
    const result = attestGhidraRawBinaryLoadImage(
      snapshot,
      target,
      { ...observation, mappings: [{ ...first, writable: true }, second] },
      ["0x8000000-0x8000001"],
    );
    if (!result.ok) throw new Error(result.error);
    expect(result.value.status).toBe("mismatch");
    if (result.value.status === "unsupported") throw new Error("unsupported");
    expect(
      result.value.checks.filter((check) => !check.matched).map((c) => c.name),
    ).toEqual(["mapping[0].writable"]);
  });

  it("reports a mismatch when Ghidra kept one unsplit block", () => {
    const { snapshot, target } = split();
    const plain = fixtureRawBinaryLoadImage();
    const result = attestGhidraRawBinaryLoadImage(
      snapshot,
      target,
      plain.observation,
      ["0x8000000-0x8000001"],
    );
    if (!result.ok) throw new Error(result.error);
    expect(result.value.status).toBe("mismatch");
  });

  it("requires one snapshot digest per piece", () => {
    const { target, observation } = split();
    const plain = fixtureRawBinaryLoadImage();
    expect(
      attestGhidraRawBinaryLoadImage(plain.snapshot, target, observation, [
        "0x8000000-0x8000001",
      ]),
    ).toEqual({
      ok: false,
      error:
        "Ghidra raw-binary read-only verification requires one snapshot digest per mapped piece",
    });
  });
});
