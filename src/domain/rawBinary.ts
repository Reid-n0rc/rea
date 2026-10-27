import { z } from "zod";

import type {
  BinaryArchitecture,
  HeaderArchitecture,
  RawOnlyArchitecture,
} from "./binaryTargetTypes.js";
import type { ExecutableFormatHint } from "./dosCom.js";
import { err, ok, type Result } from "./result.js";

/** Caller-visible CPU families admitted for headerless raw binaries. */
export const BINARY_ARCHITECTURES = [
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "6502",
  "m68k",
  "rx",
] as const satisfies readonly BinaryArchitecture[];

/** Provider-neutral CPU family for a caller-supplied raw-binary load. */
export const binaryArchitectureSchema = z.enum(BINARY_ARCHITECTURES);

const RAW_BINARY_ADDRESS = /^0x[0-9A-Fa-f]{1,16}$/u;

const addressFormatMessage = (field: "entry_point" | "base_address") =>
  `${field} must be a hexadecimal address of the form 0x…`;

/** Hexadecimal entry address; file offset 0 is mapped here unless base_address is given. */
export const rawBinaryEntryPointSchema = z
  .string()
  .regex(RAW_BINARY_ADDRESS, { message: addressFormatMessage("entry_point") });

/** Hexadecimal address where raw file offset 0 is mapped, separate from the entry. */
export const rawBinaryBaseAddressSchema = z
  .string()
  .regex(RAW_BINARY_ADDRESS, { message: addressFormatMessage("base_address") });

/** Canonicalized caller-supplied raw-binary address with the original spelling. */
export interface CanonicalRawBinaryAddress {
  readonly source: string;
  readonly canonical: string;
  readonly value: bigint;
}

const parseRawBinaryAddress = (
  value: string,
  field: "entry_point" | "base_address",
): Result<CanonicalRawBinaryAddress, string> => {
  if (!RAW_BINARY_ADDRESS.test(value)) return err(addressFormatMessage(field));
  const parsed = BigInt(value);
  return ok({
    source: value,
    canonical: `0x${parsed.toString(16)}`,
    value: parsed,
  });
};

/** Parse a caller-supplied hex entry while preserving the source spelling. */
export const parseRawBinaryEntryPoint = (
  value: string,
): Result<CanonicalRawBinaryAddress, string> =>
  parseRawBinaryAddress(value, "entry_point");

/** Reject empty or non-integral file extents for a headerless image. */
export const validateRawBinaryLength = (
  length: number,
): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1
    ? ok(null)
    : err("raw-binary requires at least one file byte");

/** Admitted headerless load identity used by target resolution and profiles. */
export interface RawBinaryAdmission {
  readonly architecture: HeaderArchitecture | RawOnlyArchitecture;
  readonly entryPoint: string;
  readonly entryPointSource: string;
  /**
   * Canonical address of file offset 0 when the caller selected one that
   * differs from the entry. Omitted means file offset 0 is mapped at the entry.
   */
  readonly baseAddress?: string;
  readonly baseAddressSource?: string;
}

/** Why a headerless load was refused, with its owning classification. */
export interface RawBinaryAdmissionRejection {
  readonly reason: string;
  /**
   * `load_selection_rejected` names a caller-input selection problem;
   * `file_format_rejected` names a refusal caused by the target file itself.
   */
  readonly constraint: "load_selection_rejected" | "file_format_rejected";
}

const addressWidth = (architecture: BinaryArchitecture): bigint =>
  architecture === "6502"
    ? 0xffffn
    : architecture === "x86" ||
        architecture === "arm" ||
        architecture === "m68k" ||
        architecture === "rx"
      ? 0xffffffffn
      : 0xffffffffffffffffn;

/**
 * Instruction alignment a family requires of its entry and of the mapped
 * image start. 68000-family instruction words are fetched from even addresses.
 */
// 68000-family instruction words are fetched from even addresses. RX
// instructions are variable length (1 to 8 bytes) and byte-aligned, so any
// address is a possible instruction start.
const instructionAlignment = (architecture: BinaryArchitecture): bigint =>
  architecture === "arm" || architecture === "arm64"
    ? 4n
    : architecture === "m68k"
      ? 2n
      : 1n;

const selectionRejected = (reason: string) =>
  err({ reason, constraint: "load_selection_rejected" as const });

/** Parse an optional base of file offset 0 with the family's start alignment. */
const admitRawBinaryBase = (
  value: unknown,
  architecture: BinaryArchitecture,
  alignment: bigint,
): Result<
  CanonicalRawBinaryAddress | undefined,
  RawBinaryAdmissionRejection
> => {
  if (value === undefined) return ok(undefined);
  if (typeof value !== "string")
    return selectionRejected(addressFormatMessage("base_address"));
  const base = parseRawBinaryAddress(value, "base_address");
  if (!base.ok) return selectionRejected(base.error);
  return base.value.value % alignment === 0n
    ? ok(base.value)
    : selectionRejected(
        `raw-binary ${architecture} base_address ${base.value.canonical} must be ${alignment}-byte aligned`,
      );
};

/**
 * Validate architecture, entry, the optional base of file offset 0, and that
 * the mapped image fits the CPU width and contains the entry.
 */
export const admitRawBinary = (input: {
  readonly architecture: unknown;
  readonly entryPoint: unknown;
  readonly baseAddress?: unknown;
  readonly fileBytes: number;
}): Result<RawBinaryAdmission, RawBinaryAdmissionRejection> => {
  const architecture = binaryArchitectureSchema.safeParse(input.architecture);
  if (!architecture.success)
    return selectionRejected(
      "raw-binary format requires architecture (x86, x86_64, arm, arm64, 6502, m68k, or rx)",
    );
  if (typeof input.entryPoint !== "string")
    return selectionRejected(
      "raw-binary format requires entry_point as a hexadecimal address of the form 0x…",
    );
  const entry = parseRawBinaryEntryPoint(input.entryPoint);
  if (!entry.ok) return selectionRejected(entry.error);
  const alignment = instructionAlignment(architecture.data);
  if (entry.value.value % alignment !== 0n)
    return selectionRejected(
      `raw-binary ${architecture.data} entry_point ${entry.value.canonical} must be ${alignment}-byte aligned`,
    );
  const base = admitRawBinaryBase(
    input.baseAddress,
    architecture.data,
    alignment,
  );
  if (!base.ok) return base;
  const length = validateRawBinaryLength(input.fileBytes);
  if (!length.ok)
    return err({
      reason: length.error,
      constraint: "file_format_rejected",
    });
  const start = base.value ?? entry.value;
  const last = start.value + BigInt(input.fileBytes) - 1n;
  const max = addressWidth(architecture.data);
  if (start.value > max || last > max)
    return selectionRejected(
      `raw-binary mapping from ${start.canonical} must fit in the ${architecture.data} address width`,
    );
  if (entry.value.value < start.value || entry.value.value > last)
    return selectionRejected(
      `raw-binary entry_point ${entry.value.canonical} must lie inside the mapped image ${start.canonical}..0x${last.toString(16)}`,
    );
  return ok({
    architecture: architecture.data,
    entryPoint: entry.value.canonical,
    entryPointSource: entry.value.source,
    // A base equal to the entry is today's mapping; it shares that identity.
    ...(base.value === undefined || base.value.value === entry.value.value
      ? {}
      : {
          baseAddress: base.value.canonical,
          baseAddressSource: base.value.source,
        }),
  });
};

/** Describe the format/architecture/entry/base pairing without performing I/O. */
export const rawBinarySelectionError = (input: {
  readonly format?: ExecutableFormatHint;
  readonly architecture?: unknown;
  readonly entryPoint?: unknown;
  readonly baseAddress?: unknown;
}): string | undefined => {
  const hasArchitecture = input.architecture !== undefined;
  const hasEntry = input.entryPoint !== undefined;
  const hasBase = input.baseAddress !== undefined;
  if (input.format === "raw-binary") {
    if (!hasArchitecture || !hasEntry)
      return "format=raw-binary requires architecture and entry_point";
    return undefined;
  }
  if (hasBase) return "base_address applies only with format=raw-binary";
  if (input.format === "gamecube-dol") {
    // The DOL header fixes architecture; entry_point is checked against it at admission.
    return hasArchitecture
      ? "format=gamecube-dol takes its architecture from the DOL header; omit architecture"
      : undefined;
  }
  if (hasArchitecture || hasEntry)
    return "architecture and entry_point apply only with format=raw-binary";
  return undefined;
};
