import { describe, expect, it } from "vitest";

import { rizinInputSchema } from "../../src/domain/reverseEngineering.js";
import { rizinCommand } from "../../src/rizin/RizinCommand.js";

describe("rizin one-shot command arguments", () => {
  it("keeps the header-detected form when no decoder is selected", () => {
    const args = rizinCommand(
      rizinInputSchema.parse({ path: "/fw/image.bin", command: "pd 1" }),
    );
    expect(args).toEqual([
      "-N",
      "-q",
      "-e",
      "scr.color=0",
      "-c",
      "pd 1",
      "/fw/image.bin",
    ]);
  });

  it("maps arch, bits and base_address to -a, -b and -m for a headerless image", () => {
    const args = rizinCommand(
      rizinInputSchema.parse({
        path: "/fw/main.bin",
        command: "pd 3 @ 0xfffa347c",
        arch: "rx",
        bits: 32,
        base_address: "0xFFF80000",
      }),
    );
    expect(args).toEqual([
      "-N",
      "-q",
      "-e",
      "scr.color=0",
      "-a",
      "rx",
      "-b",
      "32",
      "-m",
      "0xFFF80000",
      "-c",
      "pd 3 @ 0xfffa347c",
      "/fw/main.bin",
    ]);
  });

  it.each([
    [{ arch: "-e" }, "arch must be a Rizin asm.arch plugin name"],
    [{ arch: "x86;!sh" }, "arch must be a Rizin asm.arch plugin name"],
    [{ bits: 12 }, ""],
    [
      { base_address: "fff80000" },
      "base_address must be a hexadecimal address",
    ],
  ])("rejects %j", (extra, message) => {
    const parsed = rizinInputSchema.safeParse({
      path: "/fw/main.bin",
      command: "pd 1",
      ...extra,
    });
    expect(parsed.success).toBe(false);
    if (message !== "") expect(JSON.stringify(parsed.error)).toContain(message);
  });
});
