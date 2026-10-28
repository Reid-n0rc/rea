import { describe, expect, it } from "vitest";

import { parseConfig } from "./parseConfig.js";
import {
  ghidraRawReadonlyPieces,
  ghidraRawReadonlyRangesSchema,
  MAX_GHIDRA_RAW_READONLY_RANGES,
} from "./ghidraRawReadonlyRanges.js";

describe("REA_GHIDRA_RAW_READONLY_RANGES", () => {
  it("canonicalizes, sorts and drops blank entries", () => {
    expect(
      ghidraRawReadonlyRangesSchema.parse(
        " 0x208000-0x2080FF ,, 0X200000-0x206fff ",
      ),
    ).toEqual(["0x200000-0x206fff", "0x208000-0x2080ff"]);
    expect(ghidraRawReadonlyRangesSchema.parse(" , ")).toBeUndefined();
    expect(ghidraRawReadonlyRangesSchema.parse("0x10-0x10")).toEqual([
      "0x10-0x10",
    ]);
  });

  it.each([
    ["0x200000", "must be an inclusive 0xstart-0xend"],
    ["200000-206fff", "must be an inclusive 0xstart-0xend"],
    ["0x2000-0x1000", "must not end before it starts"],
    ["0x1000-0x2000,0x2000-0x3000", "overlap"],
    ["0x1-0x2-0x3", "must be an inclusive 0xstart-0xend"],
  ])("rejects %s", (value, message) => {
    const parsed = ghidraRawReadonlyRangesSchema.safeParse(value);
    expect(parsed.success).toBe(false);
    expect(JSON.stringify(parsed.error?.issues)).toContain(message);
  });

  it("bounds the number of ranges", () => {
    const ranges = Array.from(
      { length: MAX_GHIDRA_RAW_READONLY_RANGES + 1 },
      (_, index) =>
        `0x${(index * 2).toString(16)}-0x${(index * 2).toString(16)}`,
    ).join(",");
    expect(ghidraRawReadonlyRangesSchema.safeParse(ranges).success).toBe(false);
  });

  it("reaches the parsed configuration and refuses invalid values by setting name", () => {
    const parsed = parseConfig({
      GHIDRA_INSTALL_DIR: "/ghidra",
      REA_GHIDRA_RAW_READONLY_RANGES: "0x200000-0x206fff",
    });
    if (!parsed.ok) throw parsed.error;
    expect(parsed.value.ghidraRawReadonlyRanges).toEqual(["0x200000-0x206fff"]);
    const invalid = parseConfig({
      GHIDRA_INSTALL_DIR: "/ghidra",
      REA_GHIDRA_RAW_READONLY_RANGES: "rodata",
    });
    expect(invalid.ok).toBe(false);
    if (!invalid.ok)
      expect(JSON.stringify(invalid.error)).toContain(
        "REA_GHIDRA_RAW_READONLY_RANGES",
      );
  });

  it("tiles the file into writable and read-only pieces", () => {
    expect(
      ghidraRawReadonlyPieces(0x1000n, 0x10ffn, [
        { start: 0x1000n, end: 0x103fn },
        { start: 0x1080n, end: 0x108fn },
      ]),
    ).toEqual([
      { start: 0x1000n, end: 0x103fn, readonly: true },
      { start: 0x1040n, end: 0x107fn, readonly: false },
      { start: 0x1080n, end: 0x108fn, readonly: true },
      { start: 0x1090n, end: 0x10ffn, readonly: false },
    ]);
    expect(
      ghidraRawReadonlyPieces(0x1000n, 0x10ffn, [
        { start: 0x1000n, end: 0x10ffn },
      ]),
    ).toEqual([{ start: 0x1000n, end: 0x10ffn, readonly: true }]);
  });
});
