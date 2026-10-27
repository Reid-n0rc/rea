import { describe, expect, it } from "vitest";

import { openBinaryInputSchema } from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
  it("accepts base_address only with format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000100",
        base_address: "0x8000000",
      }).success,
    ).toBe(true);
    for (const format of [undefined, "dos-com", "gamecube-dol"] as const) {
      const parsed = openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        ...(format === undefined ? {} : { format }),
        base_address: "0x8000000",
      });
      expect(parsed.success).toBe(false);
      expect(parsed.error?.issues).toEqual([
        expect.objectContaining({
          path: ["base_address"],
          message: "base_address applies only with format=raw-binary",
        }),
      ]);
    }
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000100",
        base_address: "8000000",
      }).success,
    ).toBe(false);
  });
});
