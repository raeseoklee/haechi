import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const ALG = "AES-256-GCM";

export function createLocalCryptoProvider({ keyFile }) {
  if (!keyFile) {
    throw new Error("Local crypto provider requires keyFile");
  }

  let cachedKey = null;

  async function loadKey() {
    if (cachedKey) {
      return cachedKey;
    }
    const raw = JSON.parse(await readFile(keyFile, "utf8"));
    if (!raw.keys?.length) {
      throw new Error(`No keys found in ${keyFile}`);
    }
    const active = raw.keys.find((key) => key.status === "active") ?? raw.keys[0];
    cachedKey = {
      kid: active.kid,
      key: Buffer.from(active.k, "base64url")
    };
    if (cachedKey.key.length !== 32) {
      throw new Error("AES-256-GCM local key must be 32 bytes");
    }
    return cachedKey;
  }

  return {
    id: "haechi.crypto.local-aes-gcm",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: false
    },
    async encrypt({ plaintext, aad }) {
      const { kid, key } = await loadKey();
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
      const { key } = await loadKey();
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
      const aadBytes = Buffer.from(canonicalize(aad), "utf8");
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

  if (!force) {
    try {
      await readFile(keyFile, "utf8");
      return { created: false, keyFile };
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
    }
  }

  const key = {
    version: 1,
    createdAt: new Date().toISOString(),
    keys: [
      {
        kid: `local-${Date.now()}`,
        kty: "oct",
        alg: ALG,
        status: "active",
        k: randomBytes(32).toString("base64url")
      }
    ]
  };

  await writeFile(keyFile, `${JSON.stringify(key, null, 2)}\n`, { mode: 0o600 });
  return { created: true, keyFile };
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
