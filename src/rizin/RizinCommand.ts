import type { RizinInput } from "../domain/reverseEngineering.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

export const RIZIN_PROVIDER_IDENTITY = {
  id: "rizin",
  name: "Rizin",
  version: null,
} as const;

/**
 * Default one-shot presentation to plain text while retaining plugin
 * availability. Optional arch, bits and base_address select the decoder and
 * load address for a headerless image (rizin -a, -b, -m).
 */
export const rizinCommand = (input: RizinInput): readonly string[] => [
  "-N",
  "-q",
  "-e",
  "scr.color=0",
  ...(input.arch === undefined ? [] : ["-a", input.arch]),
  ...(input.bits === undefined ? [] : ["-b", String(input.bits)]),
  ...(input.base_address === undefined ? [] : ["-m", input.base_address]),
  "-c",
  input.command,
  absoluteCallerPath(input.path),
];
