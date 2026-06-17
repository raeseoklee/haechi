import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createLocalCryptoProvider, initLocalKeyFile } from "haechi/crypto";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createJwtAuthProvider } from "./index.mjs";

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

async function makeProvider({ keys, jwks, overrides = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "haechi-jwt-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const cryptoProvider = createLocalCryptoProvider({ keyFile });
  return createJwtAuthProvider({
    issuer: ISSUER, audience: AUD, jwksUri: JWKS_URI, cryptoProvider,
    fetchImpl: jwksFetch(jwks ?? { keys: [keys.rsaJwk, keys.ecJwk] }),
    lookupImpl: PUBLIC_LOOKUP,
    now: () => NOW_MS,
    ...overrides
  });
}
const req = (jwt) => ({ headers: { authorization: `Bearer ${jwt}` } });

test("a valid RS256 token authenticates into a PII-safe identity (no raw sub/iss)", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ scope: "read write" }), privateKey: keys.rsa.privateKey });
  const id = await provider.authenticate(req(jwt));
  assert.ok(id, "expected an identity");
  assert.equal(id.provider, "jwt");
  assert.equal(id.type, "user");
  assert.match(id.subjectHash, /^[a-f0-9]{64}$/);
  assert.match(id.issuerHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(id.scopes, ["read", "write"]);
  // raw values never present
  const serialized = JSON.stringify(id);
  assert.doesNotMatch(serialized, /user-123/);
  assert.doesNotMatch(serialized, /idp\.example\.com/);
});

test("a valid ES256 token authenticates (ieee-p1363 signature encoding)", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const jwt = signJwt({ alg: "ES256", kid: "ec-1", claims: baseClaims(), privateKey: keys.ec.privateKey });
  const id = await provider.authenticate(req(jwt));
  assert.ok(id);
  assert.equal(id.provider, "jwt");
});

test("alg:none is rejected", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const h = b64url(JSON.stringify({ alg: "none", kid: "rsa-1" }));
  const p = b64url(JSON.stringify(baseClaims()));
  assert.equal(await provider.authenticate(req(`${h}.${p}.`)), null);
});

test("alg-confusion: an HS256 token forged with the RSA public key as the MAC secret is rejected", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  // attacker uses the RSA public key (PEM) as an HMAC secret
  const { createHmac } = await import("node:crypto");
  const pubPem = keys.rsa.publicKey.export({ type: "spki", format: "pem" });
  const h = b64url(JSON.stringify({ alg: "HS256", kid: "rsa-1" }));
  const p = b64url(JSON.stringify(baseClaims()));
  const mac = createHmac("sha256", pubPem).update(`${h}.${p}`).digest("base64url");
  assert.equal(await provider.authenticate(req(`${h}.${p}.${mac}`)), null); // HS* not in allowlist
});

test("a token signed by a different key (bad signature) is rejected", async () => {
  const keys = makeKeys();
  const other = makeKeys();
  const provider = await makeProvider({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims(), privateKey: other.rsa.privateKey });
  assert.equal(await provider.authenticate(req(jwt)), null);
});

test("expired (exp) and not-yet-valid (nbf) are rejected; missing exp is rejected", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const expired = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ exp: NOW_S - 3600 }), privateKey: keys.rsa.privateKey });
  const future = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ nbf: NOW_S + 3600 }), privateKey: keys.rsa.privateKey });
  const noExp = baseClaims(); delete noExp.exp;
  const missingExp = signJwt({ alg: "RS256", kid: "rsa-1", claims: noExp, privateKey: keys.rsa.privateKey });
  assert.equal(await provider.authenticate(req(expired)), null);
  assert.equal(await provider.authenticate(req(future)), null);
  assert.equal(await provider.authenticate(req(missingExp)), null);
});

test("wrong aud (string and array) and wrong iss are rejected; missing/empty sub is rejected", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const wrongAud = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: "someone-else" }), privateKey: keys.rsa.privateKey });
  const wrongAudArr = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: ["a", "b"] }), privateKey: keys.rsa.privateKey });
  const okAudArr = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: ["x", AUD] }), privateKey: keys.rsa.privateKey });
  const wrongIss = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ iss: "https://evil.example.com" }), privateKey: keys.rsa.privateKey });
  const emptySub = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ sub: "" }), privateKey: keys.rsa.privateKey });
  assert.equal(await provider.authenticate(req(wrongAud)), null);
  assert.equal(await provider.authenticate(req(wrongAudArr)), null);
  assert.ok(await provider.authenticate(req(okAudArr)));   // audience present in the array → ok
  assert.equal(await provider.authenticate(req(wrongIss)), null);
  assert.equal(await provider.authenticate(req(emptySub)), null);
});

test("missing kid and unknown kid are rejected", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const noKid = (() => {
    const h = b64url(JSON.stringify({ alg: "RS256" }));
    const p = b64url(JSON.stringify(baseClaims()));
    const input = `${h}.${p}`;
    const s = sign("sha256", Buffer.from(input), keys.rsa.privateKey);
    return `${input}.${b64url(s)}`;
  })();
  const unknownKid = signJwt({ alg: "RS256", kid: "nope", claims: baseClaims(), privateKey: keys.rsa.privateKey });
  assert.equal(await provider.authenticate(req(noKid)), null);
  assert.equal(await provider.authenticate(req(unknownKid)), null);
});

test("a JWE-style typ header is rejected (only JWS accepted)", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims(), privateKey: keys.rsa.privateKey, header: { typ: "JWE" } });
  assert.equal(await provider.authenticate(req(jwt)), null);
});

test("an RSA key below 2048 bits is rejected", async () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const weakJwk = { ...weak.publicKey.export({ format: "jwk" }), kid: "weak", use: "sig" };
  const provider = await makeProvider({ keys: makeKeys(), jwks: { keys: [weakJwk] } });
  const jwt = signJwt({ alg: "RS256", kid: "weak", claims: baseClaims(), privateKey: weak.privateKey });
  assert.equal(await provider.authenticate(req(jwt)), null);
});

test("a JWK marked use:enc / key_ops:[encrypt] is rejected", async () => {
  const keys = makeKeys();
  const encJwk = { ...keys.rsaJwk, kid: "enc-1", use: "enc" };
  const opsJwk = { ...keys.rsaJwk, kid: "ops-1", use: undefined, key_ops: ["encrypt"] };
  const provider = await makeProvider({ keys, jwks: { keys: [encJwk, opsJwk] } });
  const a = signJwt({ alg: "RS256", kid: "enc-1", claims: baseClaims(), privateKey: keys.rsa.privateKey });
  const b = signJwt({ alg: "RS256", kid: "ops-1", claims: baseClaims(), privateKey: keys.rsa.privateKey });
  assert.equal(await provider.authenticate(req(a)), null);
  assert.equal(await provider.authenticate(req(b)), null);
});

test("a malformed (non-base64url) token is rejected without throwing", async () => {
  const provider = await makeProvider({ keys: makeKeys() });
  assert.equal(await provider.authenticate(req("not.a.jwt!!")), null);
  assert.equal(await provider.authenticate(req("only-two.parts")), null);
  assert.equal(await provider.authenticate({ headers: {} }), null);
});

test("JWKS refetch is bounded to one per cooldown — across flood, staleness, and a stale+unknown kid", async () => {
  const keys = makeKeys();
  let fetches = 0;
  let clock = NOW_MS;
  const provider = await makeProvider({
    keys,
    overrides: {
      now: () => clock,
      jwksTtlMs: 300_000,
      jwksCooldownMs: 60_000,
      fetchImpl: async () => { fetches += 1; return new Response(JSON.stringify({ keys: [keys.rsaJwk] }), { status: 200 }); }
    }
  });
  const ghost = (i) => signJwt({ alg: "RS256", kid: `ghost-${i}`, claims: baseClaims(), privateKey: keys.rsa.privateKey });

  // prime the cache (fetch #1)
  assert.ok(await provider.authenticate(req(signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims(), privateKey: keys.rsa.privateKey }))));
  assert.equal(fetches, 1);

  // flood unknown kids WITHIN the cooldown → no refetch (we just fetched)
  for (let i = 0; i < 5; i += 1) await provider.authenticate(req(ghost(i)));
  assert.equal(fetches, 1, "flood within cooldown must not refetch");

  // after the cooldown, one unknown kid → exactly ONE refetch; the rest are gated
  clock += 61_000;
  for (let i = 0; i < 5; i += 1) await provider.authenticate(req(ghost(10 + i)));
  assert.equal(fetches, 2, "flood after cooldown must refetch exactly once");

  // REGRESSION (was a double-refetch bug): cache STALE (past TTL) + unknown kid
  // in one call must trigger exactly ONE fetch, not two.
  clock += 400_000; // > TTL and > cooldown
  await provider.authenticate(req(ghost(99)));
  assert.equal(fetches, 3, "stale cache + unknown kid must refetch exactly once, not twice");
});

test("a whitespace-only sub is rejected (non-empty means meaningful)", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  for (const sub of ["   ", "\t", "\n"]) {
    const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ sub }), privateKey: keys.rsa.privateKey });
    assert.equal(await provider.authenticate(req(jwt)), null);
  }
});

test("a heterogeneous aud array (non-string elements) is rejected even if the audience is present", async () => {
  const keys = makeKeys();
  const provider = await makeProvider({ keys });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ aud: [123, null, AUD] }), privateKey: keys.rsa.privateKey });
  assert.equal(await provider.authenticate(req(jwt)), null);
});

test("construction fails closed on bad config", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-jwt-cfg-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const cryptoProvider = createLocalCryptoProvider({ keyFile });
  const base = { issuer: ISSUER, audience: AUD, jwksUri: JWKS_URI, cryptoProvider };
  assert.throws(() => createJwtAuthProvider({ ...base, cryptoProvider: {} }), /cryptoProvider/);
  assert.throws(() => createJwtAuthProvider({ ...base, jwksUri: "http://idp.example.com/jwks" }), /https/);
  assert.throws(() => createJwtAuthProvider({ ...base, jwksUri: "https://cdn.other.com/jwks" }), /issuer host/);
  assert.throws(() => createJwtAuthProvider({ ...base, issuer: "urn:tenant:1" }), /issuer/);
  assert.throws(() => createJwtAuthProvider({ issuer: "https://169.254.169.254", audience: AUD, jwksUri: "https://169.254.169.254/jwks", cryptoProvider }), /blocked/);
  // IPv6 link-local across the full fe80::/10 (not just fe80), and multicast,
  // plus P1-CR-002 IPv4-mapped IPv6 — both DOTTED and HEX forms must be blocked
  // (7f00:1 == 127.0.0.1, a00:1 == 10.0.0.1, a9fe:a9fe == 169.254.169.254).
  for (const ip of [
    "[fe80::1]", "[fe81::1]", "[febf::1]", "[ff02::1]", "[::1]",
    "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::ffff:7f00:0001]",
    "[::ffff:10.0.0.1]", "[::ffff:a00:1]", "[::ffff:c0a8:1]", "[::ffff:a9fe:a9fe]"
  ]) {
    assert.throws(() => createJwtAuthProvider({ issuer: `https://${ip}`, audience: AUD, jwksUri: `https://${ip}/jwks`, cryptoProvider }), /blocked/, `expected ${ip} blocked`);
  }
  // A genuinely public IPv4-mapped IPv6 (hex 808:808 == 8.8.8.8) must NOT be
  // over-blocked: it is allowed past the SSRF guard (and fails later for an
  // unrelated reason — never with /blocked/).
  for (const ip of ["[::ffff:8.8.8.8]", "[::ffff:808:808]"]) {
    assert.doesNotThrow(
      () => { try { createJwtAuthProvider({ issuer: `https://${ip}`, audience: AUD, jwksUri: `https://${ip}/jwks`, cryptoProvider }); } catch (e) { if (/blocked/.test(e.message)) throw e; } },
      `public mapped ${ip} must not be SSRF-blocked`
    );
  }
  assert.throws(() => createJwtAuthProvider({ ...base, clockSkewSeconds: 301 }), /clockSkew/);
  assert.throws(() => createJwtAuthProvider({ ...base, algorithms: ["HS256"] }), /unsafe|Unsupported/);
  assert.throws(() => createJwtAuthProvider({ ...base, algorithms: ["none"] }), /unsafe|Unsupported/);
  // trustedEndpointHosts passes through to the verifier: a URL-shaped / port-
  // bearing / non-array entry fails closed at construction; a private/loopback
  // allowlist entry never bypasses the SSRF guard.
  assert.throws(() => createJwtAuthProvider({ ...base, trustedEndpointHosts: "host" }), /trustedEndpointHosts must be an array/);
  assert.throws(() => createJwtAuthProvider({ ...base, trustedEndpointHosts: ["https://cdn.other.com"] }), /bare hostname/);
  assert.throws(() => createJwtAuthProvider({ ...base, trustedEndpointHosts: ["cdn.other.com:443"] }), /bare hostname/);
  assert.throws(() => createJwtAuthProvider({ issuer: "https://login.contoso.com", audience: AUD, jwksUri: "https://127.0.0.1/jwks", trustedEndpointHosts: ["127.0.0.1"], cryptoProvider }), /blocked/);
});

test("DEFAULT (provider): a cross-host jwksUri still throws when trustedEndpointHosts is unset", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-jwt-mo-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const cryptoProvider = createLocalCryptoProvider({ keyFile });
  assert.throws(
    () => createJwtAuthProvider({ issuer: "https://login.contoso.com", audience: AUD, jwksUri: "https://contoso.b2clogin.com/jwks", cryptoProvider, lookupImpl: PUBLIC_LOOKUP }),
    /issuer host/
  );
});

test("ALLOWLISTED (provider): a trustedEndpointHosts entry lets a different JWKS host authenticate end-to-end", async () => {
  const keys = makeKeys();
  const MO_ISSUER = "https://login.contoso.com";
  const provider = await makeProvider({
    keys,
    overrides: {
      issuer: MO_ISSUER,
      jwksUri: "https://contoso.b2clogin.com/.well-known/jwks.json",
      trustedEndpointHosts: ["contoso.b2clogin.com"]
    }
  });
  const jwt = signJwt({ alg: "RS256", kid: "rsa-1", claims: baseClaims({ iss: MO_ISSUER, scope: "read" }), privateKey: keys.rsa.privateKey });
  const id = await provider.authenticate(req(jwt));
  assert.ok(id, "expected an identity from the allowlisted JWKS host");
  assert.equal(id.provider, "jwt");
  assert.deepEqual(id.scopes, ["read"]);
});
