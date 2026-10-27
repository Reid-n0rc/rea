import type { RawBinaryAdmission } from "../domain/rawBinary.js";

/** Bound Ghidra language for a caller-supplied raw-binary architecture. */
export interface GhidraRawBinaryLanguage {
  readonly languageId: string;
  readonly compilerSpecId: "default" | "gcc";
  readonly defaultAddressSpace: "ram" | "RAM";
  /**
   * Present when the language is not shipped with Ghidra. Admission requires
   * it in the selected installation's language catalog before analysis.
   */
  readonly communityModule?: GhidraCommunityProcessorModule;
}

/** A caller-installed processor module whose decoding REA has not verified. */
export interface GhidraCommunityProcessorModule {
  readonly name: string;
  readonly source: string;
}

const RX_PROCESSOR_MODULE: GhidraCommunityProcessorModule = {
  name: "RX",
  source: "github.com/stefan00lpf/rx-proc-ghidra",
};

/**
 * Map caller-visible CPU families to generic Ghidra languages with a
 * supported generic compiler specification. These are analysis conventions,
 * not evidence of the target's original compiler. Each family has one fixed
 * byte order: m68k is big-endian and the others are little-endian. Big-endian
 * ARM, Thumb-only, Cortex-M, and other processor variants are out of scope.
 * rx binds a community processor module rather than a stock language.
 */
export const ghidraRawBinaryLanguage = (
  architecture: RawBinaryAdmission["architecture"],
): GhidraRawBinaryLanguage => {
  switch (architecture) {
    case "6502":
      return {
        languageId: "6502:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "RAM",
      };
    case "m68k":
      // Ghidra's default 68000 language decodes the 68040 superset; no
      // MC68000-only variant is declared in the 68000 processor module.
      return {
        languageId: "68000:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "x86":
      return {
        languageId: "x86:LE:32:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "x86_64":
      return {
        languageId: "x86:LE:64:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "arm":
      return {
        languageId: "ARM:LE:32:v7",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "rx":
      // The community RX module declares one RXv1/RXv2 language, named for
      // the RX62T, with a single `ram` space and a default compiler spec.
      return {
        languageId: "rx62t:LE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
        communityModule: RX_PROCESSOR_MODULE,
      };
    case "arm64":
      return {
        languageId: "AARCH64:LE:64:v8A",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
  }
};

/** Evidence limitations owed by a language that Ghidra does not ship. */
export const ghidraRawBinaryLanguageLimitations = (
  language: GhidraRawBinaryLanguage,
): readonly string[] =>
  language.communityModule === undefined
    ? []
    : [
        `${language.languageId} comes from the community ${language.communityModule.name} processor module (${language.communityModule.source}) installed in the selected Ghidra; it is not shipped with Ghidra. REA has not established its instruction decoding, p-code, or decompilation fidelity, so instructions, references, and pseudocode from this language are unverified.`,
      ];
