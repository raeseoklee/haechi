import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { assertAuthProviderConformance, buildExternalIdentity } from "../packages/auth/index.mjs";

// A deterministic in-process cryptoProvider.hmac for the reference identity
// build (the harness never needs encrypt/decrypt). Keyed + domain-separated,
// mirroring the real provider's contract so buildExternalIdentity is exercised.
const HMAC_KEY = Buffer.from("conformance-test-key-conformance".padEnd(32, "x")).subarray(0, 32);
const referenceCrypto = {
  async hmac({ data, domain }) {
    if (!domain || typeof domain !== "string") {
      throw new Error("hmac requires a non-empty domain string");
    }
    const derived = createHmac("sha256", HMAC_KEY).update(domain).digest();
    return createHmac("sha256", derived).update(data).digest("hex");
  }
};

function bearerToken(request) {
  const header = request?.headers?.authorization ?? request?.headers?.Authorization;
  if (typeof header !== "string") {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

// The conformance harness's default vectors encode the EXPECTED outcome in a
// prefix (valid./expired./notyet./throw./~malformed~) plus a per-run random
// nonce — so a provider keys off the prefix convention but cannot hardcode the
// exact token. A reference provider that respects the contract: deny on
// missing/malformed/expired/not-yet-valid, never throw into the caller, and
// build a PII-safe identity on a valid credential.
function makeReferenceProvider({ now = Date.now() } = {}) {
  return {
    id: "test.reference.auth",
    async authenticate(request) {
      try {
        const token = bearerToken(request);
        if (!token) {
          return null; // missing
        }
        if (token.startsWith("throw.")) {
          throw new Error("simulated internal failure");
        }
        if (token.startsWith("~malformed~") || !token.includes(".")) {
          return null; // malformed
        }
        if (token.startsWith("expired.")) {
          return null; // expired per injected clock
        }
        if (token.startsWith("notyet.")) {
          return null; // not yet valid
        }
        if (token.startsWith("valid.")) {
          // The default vector encodes subject/issuer in the token as
          // "valid.<nonce>.<rand>.<subject>.<issuer>" so a provider that echoes
          // them raw would be caught by assertNoRawPii. A conformant provider
          // MUST keyed-hash them via buildExternalIdentity, never return raw.
          const parts = token.split(".");
          // At minimum: valid, nonce, rand (3 parts); subject/issuer are the
          // last two parts when the default-vector format is used.
          const subject = parts.length >= 5 ? parts[parts.length - 2] : `sub-of-${token}`;
          const issuer = parts.length >= 5 ? parts[parts.length - 1] : `iss-of-${token}`;
          return buildExternalIdentity(
            { provider: "plugin:test", subject, issuer, type: "user", scopes: [], labels: {} },
            referenceCrypto
          );
        }
        return null;
      } catch {
        // Contract: an internal throw surfaces to the caller as null.
        return null;
      }
    }
  };
}

test("assertAuthProviderConformance: a reference in-process provider passes", async () => {
  const result = await assertAuthProviderConformance(makeReferenceProvider());
  assert.equal(result.ok, true, JSON.stringify(result.failures));
  assert.deepEqual(result.failures, []);
});

test("assertAuthProviderConformance: vectors are randomized per run", async () => {
  // Two runs must use different generated tokens, proving a plugin can't
  // hardcode them. We capture the credentials the provider observes.
  const seen = new Set();
  const capturing = {
    id: "capture",
    async authenticate(request) {
      const token = bearerToken(request);
      if (token) {
        seen.add(token);
      }
      // Behave correctly enough not to matter; we only inspect `seen`.
      if (token?.startsWith("valid.")) {
        const parts = token.split(".");
        const subject = parts.length >= 5 ? parts[parts.length - 2] : `s-${token}`;
        const issuer = parts.length >= 5 ? parts[parts.length - 1] : `i-${token}`;
        return buildExternalIdentity(
          { provider: "plugin:test", subject, issuer },
          referenceCrypto
        );
      }
      return null;
    }
  };
  await assertAuthProviderConformance(capturing).catch(() => {});
  const firstRun = new Set(seen);
  seen.clear();
  await assertAuthProviderConformance(capturing).catch(() => {});
  // No valid/expired/etc. token from the first run reappears in the second.
  const overlap = [...firstRun].filter((t) => seen.has(t));
  assert.equal(overlap.length, 0, "randomized vectors must not repeat across runs");
});

// ---- negative tests: the harness is not vacuous ---------------------------

test("conformance FAILS a provider that throws instead of returning null", async () => {
  const broken = {
    id: "throws",
    async authenticate(request) {
      const token = bearerToken(request);
      if (token?.startsWith("throw.")) {
        throw new Error("leaks the throw to the caller");
      }
      if (token?.startsWith("valid.")) {
        return buildExternalIdentity(
          { provider: "plugin:test", subject: `s-${token}`, issuer: `i-${token}` },
          referenceCrypto
        );
      }
      return null;
    }
  };
  const result = await assertAuthProviderConformance(broken);
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /propagated an internal throw|surfaces to the caller/);
});

test("conformance FAILS a provider that returns a raw-subject identity (PII leak)", async () => {
  // Drive the harness with KNOWN vectors so the broken provider can echo the
  // exact raw subject the harness injected — the negative-control for the
  // PII-safety assertion. (The default vectors are random, so a leak can only
  // be demonstrated against a known subject/issuer.)
  const VECTOR = {
    subject: "raw-subject-value",
    issuer: "raw-issuer-value",
    missing: { request: { headers: {} } },
    malformed: { request: { headers: { authorization: "Bearer ~malformed~" } } },
    expired: { request: { headers: { authorization: "Bearer expired.x" } } },
    notYetValid: { request: { headers: { authorization: "Bearer notyet.x" } } },
    throwing: { request: { headers: { authorization: "Bearer throw.x" } } },
    valid: {
      request: { headers: { authorization: "Bearer valid.x" } },
      subject: "raw-subject-value",
      issuer: "raw-issuer-value"
    }
  };
  const broken = {
    id: "raw-subject",
    async authenticate(request) {
      const token = bearerToken(request);
      if (token?.startsWith("valid.")) {
        // BUG: surfaces a field whose value equals the raw input subject/issuer.
        return { subjectHash: "h", issuerHash: "h2", rawSubject: VECTOR.subject, rawIssuer: VECTOR.issuer };
      }
      return null;
    }
  };
  const result = await assertAuthProviderConformance(broken, { vectors: VECTOR });
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /raw subject|raw issuer|PII leak/);
});

test("conformance FAILS a provider that accepts an expired credential", async () => {
  const broken = {
    id: "accepts-expired",
    async authenticate(request) {
      const token = bearerToken(request);
      if (!token) {
        return null;
      }
      if (token.startsWith("~malformed~") || !token.includes(".")) {
        return null;
      }
      if (token.startsWith("throw.")) {
        return null;
      }
      // BUG: accepts expired/not-yet-valid as if valid.
      return buildExternalIdentity(
        { provider: "plugin:test", subject: `s-${token}`, issuer: `i-${token}` },
        referenceCrypto
      );
    }
  };
  const result = await assertAuthProviderConformance(broken);
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /expired|not-yet-valid/);
});

test("conformance FAILS a provider that leaks raw subject/issuer via DEFAULT vectors (PII check is non-vacuous)", async () => {
  // FIX C: The default randomAuthVectors now encode subject/issuer into the
  // valid credential token ("valid.<nonce>.<rand>.<subject>.<issuer>").
  // A provider that extracts and echoes them raw fails assertNoRawPii WITHOUT
  // any custom vectors being supplied — proving the default-path check is
  // non-vacuous (a leaking provider is caught even without test harness setup).
  const broken = {
    id: "leaks-raw-pii-default",
    async authenticate(request) {
      const token = bearerToken(request);
      if (!token) return null;
      if (token.startsWith("throw.")) return null;
      if (token.startsWith("~malformed~") || !token.includes(".")) return null;
      if (token.startsWith("expired.") || token.startsWith("notyet.")) return null;
      if (token.startsWith("valid.")) {
        // BUG: extracts subject/issuer from the token and echoes them raw.
        const parts = token.split(".");
        const rawSubject = parts.length >= 5 ? parts[parts.length - 2] : `s-${token}`;
        const rawIssuer = parts.length >= 5 ? parts[parts.length - 1] : `i-${token}`;
        return {
          subjectHash: "hashed-subject",
          issuerHash: "hashed-issuer",
          // PII leak: raw values present as extra fields
          leakedSubject: rawSubject,
          leakedIssuer: rawIssuer
        };
      }
      return null;
    }
  };
  // No custom vectors — uses the default randomized vectors.
  const result = await assertAuthProviderConformance(broken);
  assert.equal(result.ok, false, "expected conformance failure for PII-leaking provider using default vectors");
  assert.match(result.failures.join("\n"), /raw subject|raw issuer|PII leak/);
});

test("conformance FAILS a non-deterministic provider", async () => {
  let counter = 0;
  const broken = {
    id: "non-deterministic",
    async authenticate(request) {
      const token = bearerToken(request);
      if (token?.startsWith("valid.")) {
        return buildExternalIdentity(
          { provider: "plugin:test", subject: `s-${token}`, issuer: `i-${token}` },
          referenceCrypto
        );
      }
      // Deny path flips between null and a truthy identity-ish object.
      counter += 1;
      return counter % 2 === 0 ? null : { subjectHash: "x", issuerHash: "y" };
    }
  };
  const result = await assertAuthProviderConformance(broken);
  assert.equal(result.ok, false);
  assert.match(result.failures.join("\n"), /deterministic|must deny with null/);
});
