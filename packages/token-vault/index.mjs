import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";

export function createLocalTokenVault({ path, cryptoProvider }) {
  if (!path) {
    throw new Error("Local token vault requires path");
  }
  if (!cryptoProvider) {
    throw new Error("Local token vault requires cryptoProvider");
  }

  return {
    id: "haechi.token-vault.local",
    version: "0.2.0",
    capabilities: {
      readsPlaintext: true,
      storesPayload: true,
      storesPlaintext: false,
      networkEgress: false
    },
    async tokenize({ plaintext, type, context = {}, metadata = {} }) {
      const vault = await readVault(path);
      const token = `tok_${type}_${shortHash(`${plaintext}:${randomBytes(16).toString("hex")}`)}`;
      const aad = {
        purpose: "token-vault",
        token,
        type,
        context
      };
      vault.tokens[token] = {
        type,
        createdAt: new Date().toISOString(),
        metadata: sanitizeMetadata(metadata),
        envelope: await cryptoProvider.encrypt({ plaintext, aad }),
        aad
      };
      await writeVault(path, vault);
      return { token, type };
    },
    async reveal({ token, context = null }) {
      const vault = await readVault(path);
      const record = vault.tokens[token];
      if (!record) {
        throw new Error(`Unknown token: ${token}`);
      }
      const aad = context ? { ...record.aad, context } : record.aad;
      return {
        token,
        type: record.type,
        plaintext: await cryptoProvider.decrypt({ envelope: record.envelope, aad })
      };
    },
    async purge({ token }) {
      const vault = await readVault(path);
      const existed = Boolean(vault.tokens[token]);
      delete vault.tokens[token];
      await writeVault(path, vault);
      return { token, purged: existed };
    }
  };
}

export async function readVault(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
    return {
      version: 1,
      createdAt: new Date().toISOString(),
      tokens: {}
    };
  }
}

async function writeVault(path, vault) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(vault, null, 2)}\n`, { mode: 0o600 });
}

function sanitizeMetadata(metadata) {
  return Object.fromEntries(Object.entries(metadata).filter(([key]) => !["value", "plaintext", "payload"].includes(key)));
}

function shortHash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
