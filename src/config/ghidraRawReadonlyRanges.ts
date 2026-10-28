import { z } from "zod";

export const MAX_GHIDRA_RAW_READONLY_RANGES = 64;

/** One inclusive address range of a raw-binary image that Ghidra maps read-only. */
export interface GhidraRawReadonlyRange {
  readonly start: bigint;
  readonly end: bigint;
}

const rangePattern = /^(0x[0-9a-f]{1,16})-(0x[0-9a-f]{1,16})$/iu;

/** Canonical `0xstart-0xend` spelling committed to the analysis profile. */
export const formatGhidraRawReadonlyRange = (
  range: GhidraRawReadonlyRange,
): string => `0x${range.start.toString(16)}-0x${range.end.toString(16)}`;

/** Parse one canonical or caller spelling; undefined when it is not a range. */
export const parseGhidraRawReadonlyRange = (
  text: string,
): GhidraRawReadonlyRange | undefined => {
  const match = rangePattern.exec(text.trim());
  if (match?.[1] === undefined || match[2] === undefined) return undefined;
  return { start: BigInt(match[1]), end: BigInt(match[2]) };
};

/**
 * Parse `REA_GHIDRA_RAW_READONLY_RANGES`: comma-separated inclusive
 * `0xstart-0xend` load-address ranges of a raw-binary image that the import
 * pre-script splits from the file block and marks non-writable before
 * auto-analysis, so the decompiler folds constants and switch tables read from
 * them. Ranges are sorted and must not overlap; blank entries are dropped and a
 * list without ranges selects no override.
 */
export const ghidraRawReadonlyRangesSchema = z
  .string()
  .transform((value, context) => {
    const ranges: GhidraRawReadonlyRange[] = [];
    for (const item of value.split(",")) {
      if (item.trim() === "") continue;
      const range = parseGhidraRawReadonlyRange(item);
      if (range === undefined) {
        context.addIssue({
          code: "custom",
          message: `"${item.trim()}" must be an inclusive 0xstart-0xend hexadecimal range`,
        });
        return z.NEVER;
      }
      if (range.start > range.end) {
        context.addIssue({
          code: "custom",
          message: `${formatGhidraRawReadonlyRange(range)} must not end before it starts`,
        });
        return z.NEVER;
      }
      ranges.push(range);
    }
    ranges.sort((left, right) =>
      left.start < right.start ? -1 : left.start > right.start ? 1 : 0,
    );
    for (const [index, range] of ranges.entries()) {
      const previous = ranges[index - 1];
      if (previous !== undefined && range.start <= previous.end) {
        context.addIssue({
          code: "custom",
          message: `${formatGhidraRawReadonlyRange(previous)} and ${formatGhidraRawReadonlyRange(range)} overlap`,
        });
        return z.NEVER;
      }
    }
    return ranges;
  })
  .refine(
    (ranges) => ranges.length <= MAX_GHIDRA_RAW_READONLY_RANGES,
    `must list at most ${MAX_GHIDRA_RAW_READONLY_RANGES} ranges`,
  )
  .transform((ranges) =>
    ranges.length === 0
      ? undefined
      : ranges.map((range) => formatGhidraRawReadonlyRange(range)),
  );

/**
 * Pieces of the file block after splitting out the read-only ranges, in
 * address order, with `readonly` marking the selected ranges. `base` and
 * `last` are the inclusive load addresses of the file's first and last byte.
 */
export const ghidraRawReadonlyPieces = (
  base: bigint,
  last: bigint,
  ranges: readonly GhidraRawReadonlyRange[],
): readonly (GhidraRawReadonlyRange & { readonly readonly: boolean })[] => {
  const pieces: (GhidraRawReadonlyRange & { readonly readonly: boolean })[] =
    [];
  let cursor = base;
  for (const range of ranges) {
    if (range.start > cursor)
      pieces.push({ start: cursor, end: range.start - 1n, readonly: false });
    pieces.push({ ...range, readonly: true });
    cursor = range.end + 1n;
  }
  if (cursor <= last)
    pieces.push({ start: cursor, end: last, readonly: false });
  return pieces;
};
