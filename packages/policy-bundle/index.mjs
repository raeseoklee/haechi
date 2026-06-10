import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { canonicalize } from "../crypto/index.mjs";

const ALG = "HS256";

export async function signPolicyBundleFile({ policyPath, keyFile, outPath }) {
  const policy = JSON.parse(await readFile(policyPath, "utf8"));
  const bundle = signPolicyBundle(policy, { keyFile });
  await writeFile(outPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  return bundle;
}

export function signPolicyBundle(policy, { keyFile }) {
  const key = loadActiveKey(keyFile);
  const payload = {
    version: 1,
    alg: ALG,
    kid: key.kid,
    signedAt: new Date().toISOString(),
    policy
  };
  return {
    ...payload,
    signature: hmac(key.key, payload)
  };
}

export async function verifyPolicyBundleFile({ bundlePath, keyFile }) {
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  return verifyPolicyBundle(bundle, { keyFile });
}

export function loadVerifiedPolicyBundleFileSync({ bundlePath, keyFile }) {
  const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
  return verifyPolicyBundle(bundle, { keyFile });
}

export function verifyPolicyBundle(bundle, { keyFile }) {
  if (!bundle || bundle.alg !== ALG || !bundle.policy || !bundle.signature) {
    throw new Error("Invalid policy bundle");
  }
  const key = loadActiveKey(keyFile, bundle.kid);
  const payload = {
    version: bundle.version,
    alg: bundle.alg,
    kid: bundle.kid,
    signedAt: bundle.signedAt,
    policy: bundle.policy
  };
  const expected = hmac(key.key, payload);
  if (!safeEqual(expected, bundle.signature)) {
    throw new Error("Policy bundle signature verification failed");
  }
  return {
    valid: true,
    kid: bundle.kid,
    signedAt: bundle.signedAt,
    policy: bundle.policy
  };
}

function loadActiveKey(keyFile, kid = null) {
  const raw = JSON.parse(readFileSync(keyFile, "utf8"));
  const selected = kid
    ? raw.keys.find((key) => key.kid === kid)
    : raw.keys.find((key) => key.status === "active") ?? raw.keys[0];
  if (!selected) {
    throw new Error(`Signing key not found: ${kid ?? "active"}`);
  }
  return {
    kid: selected.kid,
    key: Buffer.from(selected.k, "base64url")
  };
}

const SIGNING_KEY_DOMAIN = "haechi:policy-bundle:signing:v1";

function hmac(key, payload) {
  // Domain-separated signing key: the stored key material doubles as the
  // AES-256-GCM encryption key, so it must never be used for HMAC directly.
  const signingKey = createHmac("sha256", key).update(SIGNING_KEY_DOMAIN).digest();
  return createHmac("sha256", signingKey).update(canonicalize(payload)).digest("base64url");
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
