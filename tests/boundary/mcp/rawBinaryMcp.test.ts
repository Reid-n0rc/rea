import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import { z } from "zod";

import { createServer } from "../../../src/server/createServer.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import type { AnalysisProvider } from "../../../src/application/AnalysisProvider.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { ProviderAdapterError } from "../../../src/domain/providerAdapterError.js";
import { err, ok } from "../../../src/domain/result.js";
import { observed } from "../../fixtures/analysisExecution.js";
import {
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { silentLogger } from "../../../src/logger.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../../../src/ghidra/GhidraProviderCapabilities.js";
import { RAW_ONLY_ARCHITECTURES } from "../../../src/domain/binaryTargetTypes.js";
import type { CallToolResult } from "@modelcontextprotocol/server";

const connect = async (
  provider: AnalysisProvider = createCacheProvider([]),
) => {
  const session = createTestBinarySession(provider);
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger },
  );
  const client = new Client({ name: "raw-binary-mcp", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, session };
};

const structured = (result: CallToolResult): Record<string, unknown> => {
  if (
    typeof result.structuredContent !== "object" ||
    result.structuredContent === null
  )
    throw new Error("missing structured result");
  return z.record(z.string(), z.unknown()).parse(result.structuredContent);
};

const withGhidraFixtureIdentity = (
  provider: AnalysisProvider,
): AnalysisProvider => {
  const identity = { ...GHIDRA_PROVIDER_IDENTITY, version: "12.1.4" };
  const profile = createAnalysisProfile(identity, { fixture: true });
  return {
    ...provider,
    identity: () => identity,
    capabilities: () =>
      provider.capabilities().map((capability) => ({
        ...capability,
        provider: identity,
      })),
    resolveAnalysisProfile: () => Promise.resolve(ok({ profile })),
    createClient: (target, _profile, context) => {
      const client = provider.createClient(target, profile, context);
      return {
        ...client,
        execute: async (operation, parameters, options) => {
          const result = await client.execute(operation, parameters, options);
          return result.ok
            ? ok({
                ...result.value,
                provider: identity,
                analysisProfile: profile,
              })
            : result;
        },
      };
    },
  };
};

it.each(RAW_ONLY_ARCHITECTURES)(
  "keeps %s out of detected lifecycle output contracts",
  (architecture) => {
    const schema = toolContract("open_binary").outputSchema;
    const result = {
      path: "/fixture/image.bin",
      kind: "executable",
      sha256: "a".repeat(64),
      architecture,
    };
    expect(
      schema.safeParse({ result: { ...result, format: "pe" } }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        result: { ...result, format: "raw-binary", entry_point: "0x8000" },
      }).success,
    ).toBe(true);
    const validateAdvertised = new Ajv2020({ strict: false }).compile(
      z.toJSONSchema(schema),
    );
    expect(validateAdvertised({ result: { ...result, format: "pe" } })).toBe(
      false,
    );
    expect(
      validateAdvertised({
        result: { ...result, format: "raw-binary", entry_point: "0x8000" },
      }),
    ).toBe(true);
  },
);

it.each([
  ["arm", "0x08000000", "0x8000000", "1eff2fe1"],
  ["6502", "0x008001", "0x8001", "a92a60"],
  ["m68k", "0x00001000", "0x1000", "4e714e7170014e75"],
  // RX has no entry alignment constraint; 03 is NOP and 02 is RTS.
  ["rx", "0x00001001", "0x1001", "0302"],
])(
  "opens a headerless %s image when architecture and entry are supplied",
  async (architecture, entryPoint, canonical, bytes) => {
    const root = await createTestTempDirectory("rea-raw-mcp-");
    const path = join(root, "ecu.bin");
    await writeFile(path, Buffer.from(bytes, "hex"));
    const { client } = await connect();
    const opened = await client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture,
        entry_point: entryPoint,
      },
    });
    expect(opened.isError).not.toBe(true);
    expect(structured(opened).result).toMatchObject({
      path,
      format: "raw-binary",
      kind: "executable",
      architecture,
      entry_point: canonical,
    });
  },
);

it.each([
  ["arm64", "c0035fd6", "0x8000001", "must be 4-byte aligned"],
  ["m68k", "4e75", "0x1001", "must be 2-byte aligned"],
])(
  "rejects an unaligned %s entry before selecting or starting a provider",
  async (architecture, bytes, entryPoint, reason) => {
    const root = await createTestTempDirectory("rea-raw-mcp-alignment-");
    const path = join(root, "image.bin");
    await writeFile(path, Buffer.from(bytes, "hex"));
    const { client, session } = await connect({
      ...createCacheProvider([]),
      resolveAnalysisProfile: () => {
        throw new Error("unaligned input must not select a provider");
      },
      createClient: () => {
        throw new Error("unaligned input must not launch a provider");
      },
    });
    const opened = await client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture,
        entry_point: entryPoint,
      },
    });
    expect(opened.isError).toBe(true);
    expect(JSON.stringify(opened.content)).toContain(reason);
    expect(session.activeTarget()).toBeUndefined();
  },
);

it("rejects raw-binary open requests that omit architecture", async () => {
  const root = await createTestTempDirectory("rea-raw-mcp-missing-");
  const path = join(root, "ecu.bin");
  await writeFile(path, Buffer.from("1eff2fe1", "hex"));
  const { client } = await connect();
  const opened = await client.callTool({
    name: "open_binary",
    arguments: { path, format: "raw-binary" },
  });
  expect(opened.isError).toBe(true);
});

it("reuses a canonical raw entry and replaces the session when the entry changes", async () => {
  const root = await createTestTempDirectory("rea-raw-mcp-reopen-");
  const path = join(root, "ecu.bin");
  await writeFile(path, Buffer.from("1eff2fe1", "hex"));
  const fixture = createCacheProvider([]);
  const resolved: string[] = [];
  const created: string[] = [];
  const closed: string[] = [];
  const { client, session } = await connect({
    ...fixture,
    resolveAnalysisProfile: (target) => {
      if (target.format !== "raw-binary")
        throw new Error("expected raw binary");
      resolved.push(target.entryPoint);
      return Promise.resolve(
        ok({
          profile: createAnalysisProfile(
            { ...fixture.identity(), version: "1" },
            {
              entry_point: target.entryPoint,
            },
          ),
        }),
      );
    },
    createClient: (target) => {
      if (target.format !== "raw-binary")
        throw new Error("expected raw binary");
      created.push(target.entryPoint);
      return {
        execute: (operation) => {
          if (operation !== "health" && operation !== "address_name")
            throw new Error(`unexpected fixture operation: ${operation}`);
          return Promise.resolve(observed(target.entryPoint));
        },
        close: () => {
          closed.push(target.entryPoint);
          return Promise.resolve(ok(null));
        },
      };
    },
  });
  const tools = (await client.listTools()).tools;
  const validateLifecycle = (
    name: "open_binary" | "binary_session",
    response: CallToolResult,
  ) => {
    const tool = tools.find((candidate) => candidate.name === name);
    if (tool?.outputSchema === undefined)
      throw new Error(`missing ${name} output schema`);
    const schema = z.record(z.string(), z.unknown()).parse(tool.outputSchema);
    const validate = new Ajv2020({
      strict: false,
      validateFormats: false,
    }).compile(schema);
    expect(
      validate(response.structuredContent),
      JSON.stringify(validate.errors),
    ).toBe(true);
    const parsed = toolContract(name).outputSchema.parse(
      response.structuredContent,
    );
    const target = z.record(z.string(), z.unknown()).parse(parsed.result);
    const { entry_point: _entry, ...missingEntry } = target;
    expect(validate({ ...structured(response), result: missingEntry })).toBe(
      false,
    );
    return target;
  };
  for (const entryPoint of ["0x08000000", "0x8000000", "0x09000000"]) {
    const opened = await client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture: "arm",
        entry_point: entryPoint,
      },
    });
    expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
    const canonical = `0x${BigInt(entryPoint).toString(16)}`;
    expect(validateLifecycle("open_binary", opened).entry_point).toBe(
      canonical,
    );
    const status = await client.callTool({
      name: "binary_session",
      arguments: {},
    });
    expect(status.isError, JSON.stringify(status)).not.toBe(true);
    expect(validateLifecycle("binary_session", status).entry_point).toBe(
      canonical,
    );
    const result = await client.callTool({
      name: "address_name",
      arguments: { address: entryPoint },
    });
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    expect(structured(result).normalized_result).toBe(canonical);
  }
  expect(session.analysisProfile()?.parameters.entry_point).toBe("0x9000000");
  expect(resolved).toEqual(["0x8000000", "0x9000000"]);
  expect(created).toEqual(["0x8000000", "0x9000000"]);
  expect(closed).toEqual(["0x8000000"]);
});

it.skipIf(process.platform !== "win32")(
  "does not replay a saved read after switching to a Windows junction",
  async () => {
    const root = await createTestTempDirectory("rea-raw-mcp-linked-reopen-");
    const actual = join(root, "actual");
    const linked = join(root, "linked");
    await mkdir(actual);
    const path = join(actual, "image.bin");
    await writeFile(path, Buffer.from("a92a60", "hex"));
    await symlink(actual, linked, "junction");
    const created: string[] = [];
    const executed: string[] = [];
    const fixture = createCacheProvider([]);
    const { client } = await connect(
      withGhidraFixtureIdentity({
        ...fixture,
        createClient: (target) => {
          created.push(target.sourcePath ?? target.path);
          return {
            execute: (operation) => {
              if (operation === "address_name")
                executed.push(target.sourcePath ?? target.path);
              if (
                operation === "address_name" &&
                target.sourcePath === join(linked, "image.bin")
              )
                return Promise.resolve(
                  err(new ProviderAdapterError("fixture", operation)),
                );
              return Promise.resolve(
                observed(operation === "address_name" ? "entry" : null),
              );
            },
            close: () => Promise.resolve(ok(null)),
          };
        },
      }),
    );
    const linkedPath = join(linked, "image.bin");
    for (const requested of [path, linkedPath]) {
      const opened = await client.callTool({
        name: "open_binary",
        arguments: {
          path: requested,
          format: "raw-binary",
          architecture: "6502",
          entry_point: "0x8001",
        },
      });
      expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
      const address = await client.callTool({
        name: "address_name",
        arguments: { address: "0x8001", document: "image.bin" },
      });
      expect(address.isError === true, JSON.stringify(address)).toBe(
        requested === linkedPath,
      );
    }
    expect(created).toEqual([path, linkedPath]);
    expect(executed).toEqual([path, linkedPath]);
  },
);

it.skipIf(process.platform !== "win32")(
  "reuses saved reads after a fixture admits a noncanonical Windows path",
  async () => {
    const root = await createTestTempDirectory("rea-raw-mcp-admitted-path-");
    const actual = join(root, "actual");
    const linked = join(root, "linked");
    await mkdir(actual);
    const path = join(actual, "image.bin");
    await writeFile(path, Buffer.from("a92a60", "hex"));
    await symlink(actual, linked, "junction");
    const calls: string[] = [];
    const fixture = createCacheProvider([]);
    // This fixture accepts the alias to isolate cache behavior after admission.
    // The real Ghidra verifier checks that a junction itself is rejected.
    const { client, session } = await connect(
      withGhidraFixtureIdentity({
        ...fixture,
        createClient: () => ({
          execute: (operation) => {
            if (operation === "address_name") calls.push(operation);
            return Promise.resolve(
              observed(operation === "health" ? null : "entry"),
            );
          },
          close: () => Promise.resolve(ok(null)),
        }),
      }),
    );
    const linkedPath = join(linked, "image.bin");
    const opened = await client.callTool({
      name: "open_binary",
      arguments: {
        path: linkedPath,
        format: "raw-binary",
        architecture: "6502",
        entry_point: "0x8001",
      },
    });
    expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
    expect(session.activeTarget()?.sourcePath).toBe(linkedPath);
    expect(session.activeTarget()?.path).toBe(path);
    for (const _ of [0, 1]) {
      const address = await client.callTool({
        name: "address_name",
        arguments: { address: "0x8001", document: "image.bin" },
      });
      expect(address.isError, JSON.stringify(address)).not.toBe(true);
    }
    expect(calls).toEqual(["address_name"]);
  },
);

it("maps a raw image at a separate base and replaces the session when the base changes", async () => {
  const root = await createTestTempDirectory("rea-raw-mcp-base-");
  const path = join(root, "rom.bin");
  // Two data words at the base, then `bx lr` at the entry.
  await writeFile(path, Buffer.from("efbeaddeefbeadde1eff2fe1", "hex"));
  const fixture = createCacheProvider([]);
  const resolved: (string | undefined)[] = [];
  const { client, session } = await connect({
    ...fixture,
    resolveAnalysisProfile: (target) => {
      if (target.format !== "raw-binary")
        throw new Error("expected raw binary");
      resolved.push(target.baseAddress);
      return Promise.resolve(
        ok({
          profile: createAnalysisProfile(
            { ...fixture.identity(), version: "1" },
            {
              entry_point: target.entryPoint,
              ...(target.baseAddress === undefined
                ? {}
                : { base_address: target.baseAddress }),
            },
          ),
        }),
      );
    },
    createClient: (target) => {
      if (target.format !== "raw-binary")
        throw new Error("expected raw binary");
      return {
        execute: () => Promise.resolve(observed(target.entryPoint)),
        close: () => Promise.resolve(ok(null)),
      };
    },
  });
  const tools = (await client.listTools()).tools;
  const validateAdvertised = (name: "open_binary" | "binary_session") => {
    const tool = tools.find((candidate) => candidate.name === name);
    if (tool?.outputSchema === undefined)
      throw new Error(`missing ${name} output schema`);
    return new Ajv2020({ strict: false, validateFormats: false }).compile(
      z.record(z.string(), z.unknown()).parse(tool.outputSchema),
    );
  };
  const open = (base_address?: string) =>
    client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x08000008",
        ...(base_address === undefined ? {} : { base_address }),
      },
    });
  for (const [base, canonical] of [
    ["0x08000000", "0x8000000"],
    ["0x8000000", "0x8000000"],
    ["0x08000004", "0x8000004"],
  ] as const) {
    const opened = await open(base);
    expect(opened.isError, JSON.stringify(opened)).not.toBe(true);
    expect(validateAdvertised("open_binary")(opened.structuredContent)).toBe(
      true,
    );
    expect(structured(opened).result).toMatchObject({
      entry_point: "0x8000008",
      base_address: canonical,
    });
    const status = await client.callTool({
      name: "binary_session",
      arguments: {},
    });
    expect(validateAdvertised("binary_session")(status.structuredContent)).toBe(
      true,
    );
    expect(structured(status).result).toMatchObject({
      entry_point: "0x8000008",
      base_address: canonical,
    });
  }
  // Without a base, file offset 0 is mapped at the entry as before.
  const plain = await open();
  expect(plain.isError, JSON.stringify(plain)).not.toBe(true);
  expect(structured(plain).result).not.toHaveProperty("base_address");
  expect(session.analysisProfile()?.parameters).not.toHaveProperty(
    "base_address",
  );
  // A base equal to the entry is the same mapping and keeps that session.
  const same = await open("0x8000008");
  expect(same.isError, JSON.stringify(same)).not.toBe(true);
  expect(structured(same).result).not.toHaveProperty("base_address");
  expect(resolved).toEqual(["0x8000000", "0x8000004", undefined]);
});

it.each([
  [
    { base_address: "0x8000000" },
    "base_address applies only with format=raw-binary",
  ],
  [
    {
      format: "raw-binary",
      architecture: "arm",
      entry_point: "0x8000008",
      base_address: "0x8000000",
    },
    "must lie inside the mapped image 0x8000000..0x8000007",
  ],
  [
    {
      format: "raw-binary",
      architecture: "arm",
      entry_point: "0x8000004",
      base_address: "0x8000002",
    },
    "base_address 0x8000002 must be 4-byte aligned",
  ],
] as const)(
  "rejects an invalid base selection %j before selecting a provider",
  async (selection, reason) => {
    const root = await createTestTempDirectory("rea-raw-mcp-base-reject-");
    const path = join(root, "rom.bin");
    await writeFile(path, Buffer.from("efbeadde1eff2fe1", "hex"));
    const { client, session } = await connect({
      ...createCacheProvider([]),
      resolveAnalysisProfile: () => {
        throw new Error("invalid input must not select a provider");
      },
      createClient: () => {
        throw new Error("invalid input must not launch a provider");
      },
    });
    const opened = await client.callTool({
      name: "open_binary",
      arguments: { path, ...selection },
    });
    expect(opened.isError).toBe(true);
    expect(JSON.stringify(opened.content)).toContain(reason);
    expect(session.activeTarget()).toBeUndefined();
  },
);
