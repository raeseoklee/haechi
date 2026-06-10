import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const ALG = "AES-256-GCM";

export function createLocalCryptoProvider({ keyFile }) {
  if (!keyFile) {
    throw new Error("Local crypto provider requires keyFile");
  }

  let cachedKeys = null;

  async function loadKeys() {
    if (cachedKeys) {
      return cachedKeys;
    }
    const raw = JSON.parse(await readFile(keyFile, "utf8"));
    if (!raw.keys?.length) {
      throw new Error(`No keys found in ${keyFile}`);
    }
    const byKid = new Map();
    for (const entry of raw.keys) {
      const key = Buffer.from(entry.k, "base64url");
      if (key.length !== 32) {
        throw new Error("AES-256-GCM local key must be 32 bytes");
      }
      byKid.set(entry.kid, { kid: entry.kid, key });
    }
    const activeEntry = raw.keys.find((key) => key.status === "active") ?? raw.keys[0];
    cachedKeys = {
      active: byKid.get(activeEntry.kid),
      byKid
    };
    return cachedKeys;
  }

  return {
    id: "haechi.crypto.local-aes-gcm",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: false
    },
    async encrypt({ plaintext, aad }) {
      const { active: { kid, key } } = await loadKeys();
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      cipher.setAAD(aadBytes);
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return {
        v: 1,
        alg: ALG,
        kid,
        iv: iv.toString("base64url"),
        ct: ciphertext.toString("base64url"),
        tag: tag.toString("base64url"),
        aadHash: sha256(aadBytes)
      };
    },
    async decrypt({ envelope, aad }) {
      const { active, byKid } = await loadKeys();
      if (envelope.alg && envelope.alg !== ALG) {
        throw new Error(`Unsupported local crypto algorithm: ${envelope.alg}`);
      }
      const selected = envelope.kid ? byKid.get(envelope.kid) : active;
      if (!selected) {
        throw new Error(`Unknown key id in envelope: ${envelope.kid}`);
      }
      const { key } = selected;
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
      if (envelope.aadHash && envelope.aadHash !== sha256(aadBytes)) {
        throw new Error("AAD hash mismatch");
      }
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
      decipher.setAAD(aadBytes);
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ct, "base64url")),
        decipher.final()
      ]);
      return plaintext.toString("utf8");
    }
  };
}

export async function initLocalKeyFile(keyFile, { force = false } = {}) {
  await mkdir(dirname(keyFile), { recursive: true });

  let existing = null;
  try {
    existing = JSON.parse(await readFile(keyFile, "utf8"));
    if (!force) {
      return { created: false, keyFile };
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  // Rotating with --force must not orphan existing envelopes/token vault
  // records, so prior keys are retained as retired and stay kid-addressable.
  const retiredKeys = (existing?.keys ?? []).map((key) => ({
    ...key,
    status: key.status === "active" ? "retired" : key.status
  }));

  const key = {
    version: 1,
    createdAt: new Date().toISOString(),
    keys: [
      {
        kid: `local-${Date.now()}-${randomBytes(3).toString("hex")}`,
        kty: "oct",
        alg: ALG,
        status: "active",
        k: randomBytes(32).toString("base64url")
      },
      ...retiredKeys
    ]
  };

  await writeFile(keyFile, `${JSON.stringify(key, null, 2)}\n`, { mode: 0o600 });
  return { created: true, keyFile, rotated: retiredKeys.length > 0 };
}

export function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("base64url");
}
