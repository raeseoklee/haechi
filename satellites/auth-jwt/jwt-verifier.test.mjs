// Focused tests for the standalone createJwtVerifier primitive (0.9 §2.2).
// These verify the carved-out JWS/JWKS path directly: verify() returns the
// validated CLAIMS object (not an identity — no buildExternalIdentity, no
// cryptoProvider involved), is fully fail-closed, and treats nonce as an
// opt-in extra that is a no-op when omitted. The behavior-preservation
// regression guard for the provider lives in auth-jwt.test.mjs (unchanged).

import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createJwtVerifier } from "./index.mjs";

const ISSUER = "https://idp.example.com";
const JWKS_URI = "https://idp.example.com/.well-known/jwks.json";
const AUD = "haechi-gateway";
const NOW_MS = 1_700_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const PUBLIC_LOOKUP = async () => [{ address: "93.184.216.34", family: 4 }]; // never hits real DNS

function makeKeys() {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const rsaJwk = { ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa-1", use: "sig", alg: "RS256" };
  const ecJwk = { ...ec.publicKey.export({ format: "jwk" }), kid: "ec-1", use: "sig", alg: "ES256" };
  return { rsa, ec, rsaJwk, ecJwk };
}

const SPECS = { RS256: { digest: "sha256" }, ES256: { digest: "sha256", dsaEncoding: "ieee-p1363" } };

function signJwt({ alg, kid, claims, privateKey, header }) {
  const h = b64url(JSON.stringify({ alg, kid, ...(header || {}) }));
  const p = b64url(JSON.stringify(claims));
  const input = `${h}.${p}`;
  const spec = SPECS[alg];
  const sig = sign(spec.digest, Buffer.from(input), spec.dsaEncoding ? { key: privateKey, dsaEncoding: spec.dsaEncoding } : privateKey);
  return `${input}.${b64url(sig)}`;
}

function baseClaims(extra = {}) {
  return { iss: ISSUER, aud: AUD, sub: "user-123", exp: NOW_S + 3600, nbf: NOW_S - 10, iat: NOW_S - 10, ...extra };
}

function jwksFetch(jwks) {
  return async () => new Response(JSON.stringify(jwks), { status: 200, headers: { "content-type": "application/json" } });
}

function makeVerifier({ keys, jwks, overrides = {} } = {}) {
  return createJwtVerifier({
    issuer: ISSUER, audience: AUD, jwksUri: JWKS_URI,
    fetchImpl: jwksFetch(jwks ?? { keys: [keys.rsaJwk, keys.ecJwk] }),
    lookupImpl: PUBLIC_LOOKUP,
    now: () => NOW_MS,
    ...overrides
  });
}

test("verify() returns the CLAIMS object (not an identity) for a valid RS256 token", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ scope: "read write" }), privateKey: keys.rsa.privateKey });
  const claims = await verifier.verify(jwt);
  assert.ok(claims, "expected claims");
  // Raw claims pass through — this is NOT a PII-safe identity.
  assert.equal(claims.sub, "user-123");
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.aud, AUD);
  assert.equal(claims.scope, "read write");
  // It is plainly NOT an identity object.
  assert.equal(claims.subjectHash, undefined);
  assert.equal(claims.issuerHash, undefined);
  assert.equal(claims.provider, undefined);
});

test("a valid ES256 token verifies (ieee-p1363 signature encoding)", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const jwt = signJwt({ alg: "ES256", kid: "ec-1", claims: baseClaims(), privateKey: keys.ec.privateKey });
  const claims = await verifier.verify(jwt);
  assert.ok(claims);
  assert.equal(claims.sub, "user-123");
});

test("alg:none is rejected", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const h = b64url(JSON.stringify({ alg: "none", kid: "rsa-1" }));
  const p = b64url(JSON.stringify(baseClaims()));
  assert.equal(await verifier.verify(`${h}.${p}.`), null);
});

test("a bad signature (signed by a different key) is rejected", async () => {
  const keys = makeKeys();
  const other = makeKeys();
  const verifier = makeVerifier({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims(), privateKey: other.rsa.privateKey });
  assert.equal(await verifier.verify(jwt), null);
});

test("wrong aud (string and array) is rejected; an aud array containing the audience is accepted", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const wrongAud = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: "someone-else" }), privateKey: keys.rsa.privateKey });
  const wrongAudArr = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: ["a", "b"] }), privateKey: keys.rsa.privateKey });
  const okAudArr = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: ["x", AUD] }), privateKey: keys.rsa.privateKey });
  assert.equal(await verifier.verify(wrongAud), null);
  assert.equal(await verifier.verify(wrongAudArr), null);
  assert.ok(await verifier.verify(okAudArr));
});

test("expired exp and missing exp are rejected", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const expired = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ exp: NOW_S - 3600 }), privateKey: keys.rsa.privateKey });
  const noExp = baseClaims(); delete noExp.exp;
  const missingExp = signJwt({ alg: "RS256", kid: "rsa-1", claims: noExp, privateKey: keys.rsa.privateKey });
  assert.equal(await verifier.verify(expired), null);
  assert.equal(await verifier.verify(missingExp), null);
});

test("an unknown kid is rejected", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const unknownKid = signJwt({ alg: "RS256", kid: "nope", claims: baseClaims(), privateKey: keys.rsa.privateKey });
  assert.equal(await verifier.verify(unknownKid), null);
});

test("a malformed (non-base64url) token is rejected without throwing", async () => {
  const verifier = makeVerifier({ keys: makeKeys() });
  assert.equal(await verifier.verify("not.a.jwt!!"), null);
  assert.equal(await verifier.verify("only-two.parts"), null);
  assert.equal(await verifier.verify(""), null);
});

test("nonce is opt-in: omitted -> ok; matching -> claims; wrong -> null", async () => {
  const keys = makeKeys();
  const verifier = makeVerifier({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ nonce: "n-abc" }), privateKey: keys.rsa.privateKey });

  // Omitted expectedNonce: no nonce check at all (preserves bearer behavior).
  assert.ok(await verifier.verify(jwt));

  // Matching expectedNonce: returns the claims.
  const ok = await verifier.verify(jwt, { expectedNonce: "n-abc" });
  assert.ok(ok);
  assert.equal(ok.nonce, "n-abc");

  // Wrong expectedNonce: deny.
  assert.equal(await verifier.verify(jwt, { expectedNonce: "wrong" }), null);

  // expectedNonce required but the token carries no nonce claim -> deny.
  const noNonce = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims(), privateKey: keys.rsa.privateKey });
  assert.equal(await verifier.verify(noNonce, { expectedNonce: "n-abc" }), null);
});

test("construction fails closed on bad config (no cryptoProvider involved)", async () => {
  const base = { issuer: ISSUER, audience: AUD, jwksUri: JWKS_URI };
  assert.throws(() => createJwtVerifier({ ...base, jwksUri: "http://idp.example.com/jwks" }), /https/);
  assert.throws(() => createJwtVerifier({ ...base, jwksUri: "https://cdn.other.com/jwks" }), /issuer host/);
  assert.throws(() => createJwtVerifier({ ...base, issuer: "urn:tenant:1" }), /issuer/);
  assert.throws(() => createJwtVerifier({ issuer: "https://169.254.169.254", audience: AUD, jwksUri: "https://169.254.169.254/jwks" }), /blocked/);
  for (const ip of ["[fe80::1]", "[febf::1]", "[ff02::1]", "[::1]"]) {
    assert.throws(() => createJwtVerifier({ issuer: `https://${ip}`, audience: AUD, jwksUri: `https://${ip}/jwks` }), /blocked/, `expected ${ip} blocked`);
  }
  assert.throws(() => createJwtVerifier({ ...base, clockSkewSeconds: 301 }), /clockSkew/);
  assert.throws(() => createJwtVerifier({ ...base, algorithms: ["HS256"] }), /unsafe|Unsupported/);
  assert.throws(() => createJwtVerifier({ ...base, algorithms: ["none"] }), /unsafe|Unsupported/);
});

// --- multi-origin trustedEndpointHosts allowlist (P1-SEC-026 residual) ------
// An operator-declared PINNED allowlist relaxes the SAME-HOST requirement only;
// https + SSRF guards still run unconditionally and the pin (not the discovery
// doc) decides which hosts are accepted.

const MO_ISSUER = "https://login.contoso.com/tenant";
const MO_JWKS = "https://contoso.b2clogin.com/tenant/.well-known/jwks.json";

test("DEFAULT (no trustedEndpointHosts): a cross-host jwksUri still throws (single-origin preserved)", async () => {
  assert.throws(
    () => createJwtVerifier({ issuer: MO_ISSUER, audience: AUD, jwksUri: MO_JWKS, fetchImpl: jwksFetch({ keys: [] }), lookupImpl: PUBLIC_LOOKUP, now: () => NOW_MS }),
    /issuer host/,
    "an unlisted cross-host jwksUri must throw when trustedEndpointHosts is unset"
  );
});

test("ALLOWLISTED: a trustedEndpointHosts entry lets a different JWKS host construct and verify", async () => {
  const keys = makeKeys();
  const verifier = createJwtVerifier({
    issuer: MO_ISSUER, audience: AUD, jwksUri: MO_JWKS,
    trustedEndpointHosts: ["contoso.b2clogin.com"],
    fetchImpl: jwksFetch({ keys: [keys.rsaJwk, keys.ecJwk] }),
    lookupImpl: PUBLIC_LOOKUP,
    now: () => NOW_MS
  });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ iss: MO_ISSUER }), privateKey: keys.rsa.privateKey });
  const claims = await verifier.verify(jwt);
  assert.ok(claims, "expected the token to verify against the allowlisted JWKS host");
  assert.equal(claims.iss, MO_ISSUER);
});

test("ALLOWLIST membership is case-insensitive (entries normalized to lowercase)", async () => {
  const keys = makeKeys();
  const verifier = createJwtVerifier({
    issuer: MO_ISSUER, audience: AUD, jwksUri: MO_JWKS,
    trustedEndpointHosts: ["Contoso.B2CLogin.com"],
    fetchImpl: jwksFetch({ keys: [keys.rsaJwk] }),
    lookupImpl: PUBLIC_LOOKUP,
    now: () => NOW_MS
  });
  assert.ok(await verifier.verify(signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ iss: MO_ISSUER }), privateKey: keys.rsa.privateKey })));
});

test("a non-allowlisted THIRD host still throws even when another host IS allowlisted", async () => {
  assert.throws(
    () => createJwtVerifier({
      issuer: MO_ISSUER, audience: AUD, jwksUri: "https://evil.attacker.example/jwks",
      trustedEndpointHosts: ["contoso.b2clogin.com"],
      fetchImpl: jwksFetch({ keys: [] }), lookupImpl: PUBLIC_LOOKUP, now: () => NOW_MS
    }),
    /trustedEndpointHosts/,
    "a host outside the issuer host and the allowlist must throw"
  );
});

test("SSRF STILL ENFORCED: an allowlisted private/loopback host is still blocked", async () => {
  assert.throws(
    () => createJwtVerifier({
      issuer: MO_ISSUER, audience: AUD, jwksUri: "https://127.0.0.1/jwks",
      trustedEndpointHosts: ["127.0.0.1"],
      fetchImpl: jwksFetch({ keys: [] }), lookupImpl: PUBLIC_LOOKUP, now: () => NOW_MS
    }),
    /blocked/,
    "the allowlist must not bypass isBlockedAddress"
  );
});

test("trustedEndpointHosts validation: URL-shaped / port-bearing / non-array entries throw at construction", async () => {
  const base = { issuer: MO_ISSUER, audience: AUD, jwksUri: MO_JWKS, fetchImpl: jwksFetch({ keys: [] }), lookupImpl: PUBLIC_LOOKUP, now: () => NOW_MS };
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: "contoso.b2clogin.com" }), /trustedEndpointHosts must be an array/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: ["https://contoso.b2clogin.com"] }), /bare hostname/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: ["contoso.b2clogin.com/jwks"] }), /bare hostname/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: ["contoso.b2clogin.com:443"] }), /bare hostname/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: ["contoso b2clogin"] }), /bare hostname/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: [""] }), /non-empty hostname/);
  assert.throws(() => createJwtVerifier({ ...base, trustedEndpointHosts: [123] }), /non-empty hostname/);
});
