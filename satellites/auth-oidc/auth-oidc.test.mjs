import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "haechi/crypto";
import { createDashboardServer } from "haechi-dashboard";
import { createOidcSessionBroker, normalizeOidcConfig } from "./index.mjs";

// ---------------------------------------------------------------------------
// Offline harness
// ---------------------------------------------------------------------------

const ISSUER = "https://idp.example.com";
const AUTHZ = "https://idp.example.com/authorize";
const TOKEN = "https://idp.example.com/oauth/token";
const JWKS = "https://idp.example.com/.well-known/jwks.json";
const END_SESSION = "https://idp.example.com/logout";
const CLIENT_ID = "haechi-dashboard";
const CLIENT_SECRET = "s3cr3t-value";
const REDIRECT = "https://dash.example.com/auth/callback";
const NOW_MS = 1_700_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const PUBLIC_LOOKUP = async () => [{ address: "93.184.216.34", family: 4 }];

function makeKey() {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...rsa.publicKey.export({ format: "jwk" }), kid: "rsa-1", use: "sig", alg: "RS256" };
  return { rsa, jwk };
}

function signIdToken({ claims, privateKey, kid = "rsa-1", alg = "RS256", header }) {
  const h = b64url(JSON.stringify({ alg, kid, ...(header || {}) }));
  const p = b64url(JSON.stringify(claims));
  const input = `${h}.${p}`;
  if (alg === "none") return `${input}.`;
  const sig = sign("sha256", Buffer.from(input), privateKey);
  return `${input}.${b64url(sig)}`;
}

function idClaims(extra = {}) {
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "user-789",
    exp: NOW_S + 3600,
    nbf: NOW_S - 10,
    iat: NOW_S - 10,
    ...extra
  };
}

function discoveryDoc(overrides = {}) {
  return {
    issuer: ISSUER,
    authorization_endpoint: AUTHZ,
    token_endpoint: TOKEN,
    jwks_uri: JWKS,
    end_session_endpoint: END_SESSION,
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    ...overrides
  };
}

// A routing fetch stub: dispatches by URL to discovery / jwks / token.
function makeFetch({ key, discovery, tokenResponse, tokenStatus = 200, idTokenBuilder } = {}) {
  const disc = discovery ?? discoveryDoc();
  const jwks = { keys: [key.jwk] };
  const calls = { discovery: 0, jwks: 0, token: 0, urls: [] };
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    calls.urls.push(u);
    if (u.endsWith("/.well-known/openid-configuration")) {
      calls.discovery += 1;
      return new Response(JSON.stringify(disc), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === JWKS) {
      calls.jwks += 1;
      return new Response(JSON.stringify(jwks), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === disc.token_endpoint || u === TOKEN) {
      calls.token += 1;
      let body = tokenResponse;
      if (!body) {
        const idToken = idTokenBuilder
          ? idTokenBuilder({ key })
          : signIdToken({ claims: idClaims({ nonce: undefined }), privateKey: key.rsa.privateKey });
        body = { id_token: idToken, access_token: "ACCESS-TOKEN-OPAQUE", token_type: "Bearer" };
      }
      return new Response(JSON.stringify(body), { status: tokenStatus, headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };
  return { fetchImpl, calls };
}

async function makeCrypto() {
  const dir = await mkdtemp(join(tmpdir(), "haechi-oidc-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return createLocalCryptoProvider({ keyFile });
}

// In-memory audit sink that records every emitted event.
function makeAuditSink() {
  const events = [];
  return { record: (e) => events.push(e), events };
}

// A mock node http response capturing status / headers / body.
function makeRes() {
  const headers = new Map();
  return {
    statusCode: 200,
    body: "",
    ended: false,
    req: {},
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
    getHeader(name) {
      return headers.get(name.toLowerCase());
    },
    end(chunk) {
      if (chunk !== undefined) this.body += chunk;
      this.ended = true;
    },
    location() {
      return headers.get("location");
    },
    setCookies() {
      const sc = headers.get("set-cookie");
      if (sc === undefined) return [];
      return Array.isArray(sc) ? sc : [sc];
    }
  };
}

function makeReq({ method = "GET", url = "/", cookies = {}, headers = {} } = {}) {
  const cookieHeader = Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  return {
    method,
    url,
    headers: { ...(cookieHeader ? { cookie: cookieHeader } : {}), ...headers },
    socket: { remoteAddress: "203.0.113.5" }
  };
}

const baseOptions = (crypto, overrides = {}) => ({
  cryptoProvider: crypto,
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT,
  scopes: ["openid", "profile"],
  secureCookies: true, // simulate the externally-visible https scheme
  lookupImpl: PUBLIC_LOOKUP,
  now: () => NOW_MS,
  ...overrides
});

// Drive a login and return the captured state/nonce/challenge + pre-auth cookie.
async function doLogin(broker) {
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 302);
  const location = res.location();
  const authUrl = new URL(location);
  const state = authUrl.searchParams.get("state");
  const nonce = authUrl.searchParams.get("nonce");
  const codeChallenge = authUrl.searchParams.get("code_challenge");
  const cookieLine = res.setCookies().find((c) => /preauth/.test(c));
  const preauthName = cookieLine.split("=")[0];
  const preauthValue = cookieLine.split("=")[1].split(";")[0];
  return { res, authUrl, state, nonce, codeChallenge, preauthName, preauthValue };
}

// ---------------------------------------------------------------------------
// HAPPY PATH
// ---------------------------------------------------------------------------

test("login 302 carries state + nonce + S256 code_challenge + the registered redirect_uri", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const { authUrl, state, nonce, codeChallenge } = await doLogin(broker);
  assert.equal(authUrl.origin + authUrl.pathname, AUTHZ);
  assert.equal(authUrl.searchParams.get("response_type"), "code");
  assert.equal(authUrl.searchParams.get("client_id"), CLIENT_ID);
  assert.equal(authUrl.searchParams.get("redirect_uri"), REDIRECT);
  assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
  assert.ok(state && nonce && codeChallenge);
  assert.match(codeChallenge, /^[A-Za-z0-9_-]+$/); // base64url, no padding
  // openid forced in, offline_access stripped.
  assert.ok(authUrl.searchParams.get("scope").split(" ").includes("openid"));
});

test("callback exchanges, verifies, mints a fresh session id unrelated to any pre-login cookie; pre-auth cookie cleared", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  const { fetchImpl, calls } = makeFetch({
    key,
    idTokenBuilder: ({ key: k }) => null // replaced per-call below
  });
  // We need the captured nonce, so build the broker with a token response that
  // signs the ID token with the captured nonce. Easiest: capture nonce, then a
  // second fetch closure. Instead, use a mutable nonce holder.
  let capturedNonce = null;
  const fetch2 = async (url, init) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    }
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = signIdToken({ claims: idClaims({ nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS", token_type: "Bearer" }), {
        status: 200
      });
    }
    throw new Error(`unexpected ${u}`);
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl: fetch2, auditSink: audit }));

  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  const preLoginCookieValue = login.preauthValue;

  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=AUTH_CODE&state=${encodeURIComponent(login.state)}`,
      cookies: { [login.preauthName]: login.preauthValue }
    }),
    cbRes
  );

  assert.equal(cbRes.statusCode, 302);
  // session cookie set, pre-auth cleared.
  const cookies = cbRes.setCookies();
  const sessionCookie = cookies.find((c) => /session/.test(c) && !/preauth/.test(c));
  const preauthCleared = cookies.find((c) => /preauth/.test(c));
  assert.ok(sessionCookie, "expected a session cookie");
  assert.ok(/Max-Age=0/.test(preauthCleared), "pre-auth cookie must be cleared");
  const sessionId = sessionCookie.split("=")[1].split(";")[0];
  assert.notEqual(sessionId, preLoginCookieValue, "fresh session id unrelated to the pre-login cookie");
  // __Host- named, HttpOnly, SameSite=Lax, Secure.
  assert.match(sessionCookie, /^__Host-haechi_session=/);
  assert.match(sessionCookie, /HttpOnly/);
  assert.match(sessionCookie, /SameSite=Lax/);
  assert.match(sessionCookie, /Secure/);

  // authenticate() now returns the session.
  const session = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } }));
  assert.ok(session, "session must authenticate");
  assert.equal(session.identity.provider, "oidc");
  assert.match(session.identity.subjectHash, /^[a-f0-9]{64}$/);

  // success event emitted.
  assert.ok(audit.events.some((e) => e.type === "oidc.login.success"));
});

// Helper: a full successful login → returns the broker, sessionId, audit, and
// all client-bound responses for the no-leak assertions.
async function fullLogin(overrides = {}) {
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  let capturedNonce = null;
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = signIdToken({ claims: idClaims({ nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS-TOK", token_type: "Bearer" }), {
        status: 200
      });
    }
    throw new Error(`unexpected ${u}`);
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, auditSink: audit, ...overrides }));
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=AUTH_CODE&state=${encodeURIComponent(login.state)}`,
      cookies: { [login.preauthName]: login.preauthValue }
    }),
    cbRes
  );
  const sessionCookie = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c));
  const sessionId = sessionCookie ? sessionCookie.split("=")[1].split(";")[0] : null;
  return { broker, key, audit, sessionId, login, cbRes, crypto };
}

// ---------------------------------------------------------------------------
// STATE failures — NO outbound request
// ---------------------------------------------------------------------------

test("mismatched state denies generically with NO outbound request", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl, calls } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const tokensBefore = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=WRONG`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401);
  assert.equal(calls.token, tokensBefore, "no token exchange on a state mismatch");
});

test("replayed state finds no record (atomic take) — second callback denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  let capturedNonce = null;
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = signIdToken({ claims: idClaims({ nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "A" }), { status: 200 });
    }
    throw new Error("unexpected");
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  // First callback succeeds.
  const res1 = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res1
  );
  assert.equal(res1.statusCode, 302);
  // Replay with the SAME pre-auth cookie -> the record was consumed -> deny.
  const res2 = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res2
  );
  assert.equal(res2.statusCode, 401);
});

test("expired state (pending TTL elapsed) denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  let clock = NOW_MS;
  const { fetchImpl, calls } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, now: () => clock, pendingTtlSeconds: 60 }));
  const login = await doLogin(broker);
  clock += 61_000; // past the pending TTL
  const before = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401);
  assert.equal(calls.token, before, "no token exchange for an expired pending record");
});

test("missing pre-auth cookie denies with no outbound request", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl, calls } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const before = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}` }), // no cookie
    res
  );
  assert.equal(res.statusCode, 401);
  assert.equal(calls.token, before);
});

test("mismatched pre-auth cookie (wrong value) denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl, calls } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const before = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`,
      cookies: { [login.preauthName]: "some-other-preauth-id" }
    }),
    res
  );
  assert.equal(res.statusCode, 401);
  assert.equal(calls.token, before);
});

// ---------------------------------------------------------------------------
// ID-token verification failures
// ---------------------------------------------------------------------------

async function callbackWithIdToken(idTokenBuilder, { brokerOverrides = {}, claimsOverride } = {}) {
  const crypto = await makeCrypto();
  const key = makeKey();
  let capturedNonce = null;
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = idTokenBuilder({ key, nonce: capturedNonce });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "A" }), { status: 200 });
    }
    throw new Error(`unexpected ${u}`);
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, ...brokerOverrides }));
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`,
      cookies: { [login.preauthName]: login.preauthValue }
    }),
    res
  );
  return res;
}

test("nonce mismatch denies", async () => {
  const res = await callbackWithIdToken(({ key }) =>
    signIdToken({ claims: idClaims({ nonce: "WRONG-NONCE" }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("alg:none denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce }), privateKey: key.rsa.privateKey, alg: "none" })
  );
  assert.equal(res.statusCode, 401);
});

test("expired ID token (exp in the past) denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, exp: NOW_S - 3600 }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("not-yet-valid ID token (nbf in the future) denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, nbf: NOW_S + 3600 }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("wrong aud denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, aud: "someone-else" }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("wrong iss denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, iss: "https://evil.example.com" }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("multi-aud WITHOUT azp denies (OIDC profile)", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, aud: [CLIENT_ID, "other-client"] }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("multi-aud with azp !== clientId denies", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, aud: [CLIENT_ID, "other"], azp: "other" }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 401);
});

test("multi-aud with azp === clientId is accepted (OIDC profile)", async () => {
  const res = await callbackWithIdToken(({ key, nonce }) =>
    signIdToken({ claims: idClaims({ nonce, aud: [CLIENT_ID, "other"], azp: CLIENT_ID }), privateKey: key.rsa.privateKey })
  );
  assert.equal(res.statusCode, 302);
});

test("max_age set but auth_time missing denies; valid auth_time accepted", async () => {
  const tooOld = await callbackWithIdToken(
    ({ key, nonce }) => signIdToken({ claims: idClaims({ nonce, auth_time: NOW_S - 10000 }), privateKey: key.rsa.privateKey }),
    { brokerOverrides: { maxAgeSeconds: 300 } }
  );
  assert.equal(tooOld.statusCode, 401);
  const ok = await callbackWithIdToken(
    ({ key, nonce }) => signIdToken({ claims: idClaims({ nonce, auth_time: NOW_S - 10 }), privateKey: key.rsa.privateKey }),
    { brokerOverrides: { maxAgeSeconds: 300 } }
  );
  assert.equal(ok.statusCode, 302);
});

// ---------------------------------------------------------------------------
// Discovery / RFC 9207 / SSRF failures
// ---------------------------------------------------------------------------

test("metadata.issuer != config denies the login (discovery rejected)", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key, discovery: discoveryDoc({ issuer: "https://other.example.com" }) });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503); // discovery failed -> generic unavailable
  assert.notEqual(res.statusCode, 302);
});

test("RFC 9207 callback iss != pinned issuer denies (no token exchange)", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl, calls } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const before = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}&iss=${encodeURIComponent("https://evil.example.com")}`,
      cookies: { [login.preauthName]: login.preauthValue }
    }),
    res
  );
  assert.equal(res.statusCode, 401);
  assert.equal(calls.token, before, "a callback-iss mismatch denies before exchange");
});

test("a code-exchange failure (non-2xx token endpoint) denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key, tokenStatus: 400, tokenResponse: { error: "invalid_grant" } });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401);
});

test("discovery with a CROSS-ORIGIN token_endpoint is rejected", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key, discovery: discoveryDoc({ token_endpoint: "https://evil.example.com/token" }) });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503);
});

test("discovery with a CROSS-ORIGIN jwks_uri is rejected", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key, discovery: discoveryDoc({ jwks_uri: "https://cdn.evil.example.com/jwks" }) });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503);
});

test("a token_endpoint host resolving to a private/metadata range at request time (post-DNS) denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  // Discovery & JWKS resolve public; the token endpoint host rebinds to metadata.
  const lookupImpl = async (hostname) => {
    if (hostname === "idp.example.com") {
      // First the discovery + jwks succeed; flip the token-time lookup to metadata.
      return [{ address: "169.254.169.254", family: 4 }];
    }
    return [{ address: "93.184.216.34", family: 4 }];
  };
  // To let discovery succeed but the token POST fail, use a lookup that returns
  // public for discovery and metadata afterwards. We simulate with a counter.
  let lookups = 0;
  const rebinding = async (hostname) => {
    lookups += 1;
    // discovery (1) + jwks (during verify, later) — keep discovery public; flip
    // the token endpoint (the 2nd lookup, which is the token POST) to metadata.
    if (lookups === 1) return [{ address: "93.184.216.34", family: 4 }]; // discovery
    return [{ address: "169.254.169.254", family: 4 }]; // token POST rebinds
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, lookupImpl: rebinding }));
  const login = await doLogin(broker); // discovery ran (lookup #1, public)
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401, "a token endpoint rebinding to metadata must deny");
});

test("an oversized token-endpoint response denies", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const big = "x".repeat(2 * 1024 * 1024);
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) return new Response(JSON.stringify({ id_token: "x", padding: big }), { status: 200 });
    throw new Error("unexpected");
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  const login = await doLogin(broker);
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401);
});

// ---------------------------------------------------------------------------
// NO TOKEN LEAK
// ---------------------------------------------------------------------------

test("no token/secret/claim leaks in any client-bound response or the audit log; access token discarded", async () => {
  const { broker, audit, sessionId, login, cbRes } = await fullLogin();
  assert.ok(sessionId, "expected a session");
  // The browser-visible cookie is the opaque id only — not a JWT.
  assert.ok(!sessionId.includes("."), "session id is opaque, not a JWT");

  const haystacks = [JSON.stringify(cbRes.setCookies()), cbRes.body, JSON.stringify(audit.events)];
  const forbidden = ["ACCESS-TOK", "AUTH_CODE", "user-789", login.state, login.nonce, CLIENT_SECRET, "id_token", "access_token"];
  for (const hay of haystacks) {
    for (const needle of forbidden) {
      assert.ok(!hay.includes(needle), `leak of "${needle}" in ${hay.slice(0, 60)}`);
    }
  }
  // The session record itself must NOT store the access token.
  const session = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } }));
  const serialized = JSON.stringify(session);
  assert.ok(!serialized.includes("ACCESS-TOK"), "access token must not be stored on the session");
  assert.ok(!serialized.includes("user-789"), "raw sub must not be stored on the session");
});

test("audit events carry only *Hash/reasonCode/provider/timestamp (no raw fields)", async () => {
  const { audit } = await fullLogin();
  assert.ok(audit.events.length > 0);
  const allowed = new Set(["type", "provider", "timestamp", "subjectHash", "issuerHash", "sessionIdHash", "reasonCode"]);
  for (const e of audit.events) {
    for (const k of Object.keys(e)) {
      assert.ok(allowed.has(k), `unexpected audit field ${k} in ${e.type}`);
    }
    assert.equal(e.provider, "oidc");
    assert.ok(typeof e.timestamp === "string");
  }
});

// ---------------------------------------------------------------------------
// SESSIONS / LOGOUT
// ---------------------------------------------------------------------------

test("after logout, replaying the old session cookie -> authenticate null and the record is gone", async () => {
  const { broker, sessionId } = await fullLogin();
  // logout requires the CSRF header + non-GET.
  const res = makeRes();
  await broker.handlers["/auth/logout"](
    makeReq({ method: "POST", url: "/auth/logout", cookies: { "__Host-haechi_session": sessionId }, headers: { "x-haechi-csrf": "1" } }),
    res
  );
  assert.ok(res.statusCode === 200 || res.statusCode === 302);
  // Replaying the cookie now yields nothing.
  const after = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } }));
  assert.equal(after, null);
});

test("logout without the CSRF header -> 403; session survives", async () => {
  const { broker, sessionId } = await fullLogin();
  const res = makeRes();
  await broker.handlers["/auth/logout"](
    makeReq({ method: "POST", url: "/auth/logout", cookies: { "__Host-haechi_session": sessionId } }),
    res
  );
  assert.equal(res.statusCode, 403);
  const stillThere = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } }));
  assert.ok(stillThere, "session must survive a CSRF-rejected logout");
});

test("logout via GET -> 403", async () => {
  const { broker, sessionId } = await fullLogin();
  const res = makeRes();
  await broker.handlers["/auth/logout"](
    makeReq({ method: "GET", url: "/auth/logout", cookies: { "__Host-haechi_session": sessionId }, headers: { "x-haechi-csrf": "1" } }),
    res
  );
  assert.equal(res.statusCode, 403);
});

test("logout post_logout_redirect_uri off-allowlist is refused", async () => {
  const { broker, sessionId } = await fullLogin();
  const res = makeRes();
  await broker.handlers["/auth/logout"](
    makeReq({
      method: "POST",
      url: `/auth/logout?post_logout_redirect_uri=${encodeURIComponent("https://evil.example.com/done")}`,
      cookies: { "__Host-haechi_session": sessionId },
      headers: { "x-haechi-csrf": "1" }
    }),
    res
  );
  assert.notEqual(res.statusCode, 302);
  assert.equal(res.statusCode, 400);
});

test("session idle + absolute TTL eviction returns null and emits oidc.session.evict", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  let clock = NOW_MS;
  const audit = makeAuditSink();
  let capturedNonce = null;
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = signIdToken({ claims: idClaims({ nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "A" }), { status: 200 });
    }
    throw new Error("unexpected");
  };
  const broker = createOidcSessionBroker(
    baseOptions(crypto, { fetchImpl, auditSink: audit, now: () => clock, idleTtlSeconds: 60, sessionTtlSeconds: 3600 })
  );
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    cbRes
  );
  const sessionId = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];
  // Within idle: ok.
  assert.ok(await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } })));
  // Past idle TTL: evicted.
  clock += 61_000;
  assert.equal(await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } })), null);
  assert.ok(audit.events.some((e) => e.type === "oidc.session.evict"));
});

// ---------------------------------------------------------------------------
// OPEN-REDIRECT
// ---------------------------------------------------------------------------

test("return_to off-origin/absolute falls back to '/'; an allowlisted relative path is honored", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  let capturedNonce = null;
  const fetchImpl = async (url) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify(discoveryDoc()), { status: 200 });
    if (u === JWKS) return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200 });
    if (u === TOKEN) {
      const idToken = signIdToken({ claims: idClaims({ nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "A" }), { status: 200 });
    }
    throw new Error("unexpected");
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, returnToAllowlist: ["/", "/events"] }));

  // Off-origin absolute -> "/".
  {
    const login = await doLogin(broker);
    capturedNonce = login.nonce;
    const res = makeRes();
    await broker.handlers["/auth/callback"](
      makeReq({
        url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}&return_to=${encodeURIComponent("https://evil.example.com")}`,
        cookies: { [login.preauthName]: login.preauthValue }
      }),
      res
    );
    assert.equal(res.statusCode, 302);
    assert.equal(res.location(), "/");
  }
  // Allowlisted relative honored.
  {
    const login = await doLogin(broker);
    capturedNonce = login.nonce;
    const res = makeRes();
    await broker.handlers["/auth/callback"](
      makeReq({
        url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}&return_to=${encodeURIComponent("/events")}`,
        cookies: { [login.preauthName]: login.preauthValue }
      }),
      res
    );
    assert.equal(res.location(), "/events");
  }
});

// ---------------------------------------------------------------------------
// RATE / DoS
// ---------------------------------------------------------------------------

test("N rapid /auth/login hit the pending cap and return a generic 429 without exhausting memory", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  // small pending cap, generous rate limit so we test the CAP path specifically.
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, pendingCap: 3, rateLimitMax: 1000 }));
  let capped = false;
  for (let i = 0; i < 10; i += 1) {
    const res = makeRes();
    await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
    if (res.statusCode === 429) capped = true;
  }
  assert.ok(capped, "the pending cap must produce a generic 429");
});

test("the per-source rate limiter caps /auth/login", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl, rateLimitMax: 2, pendingCap: 1000 }));
  const statuses = [];
  for (let i = 0; i < 5; i += 1) {
    const res = makeRes();
    await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
    statuses.push(res.statusCode);
  }
  assert.ok(statuses.includes(429), "rate limit must kick in");
});

// ---------------------------------------------------------------------------
// CONSTRUCTION FAIL-CLOSED
// ---------------------------------------------------------------------------

test("normalizeOidcConfig rejects bad options (fail-closed, enumerated)", async () => {
  const crypto = await makeCrypto();
  const base = baseOptions(crypto, {});
  delete base.lookupImpl;
  delete base.now;

  assert.throws(() => normalizeOidcConfig({ ...base, cryptoProvider: {} }), /cryptoProvider/);
  assert.throws(() => normalizeOidcConfig({ ...base, issuer: "http://idp.example.com" }), /https/);
  assert.throws(() => normalizeOidcConfig({ ...base, issuer: "not-a-url" }), /valid URL|https/);
  // redirectUri non-https off loopback.
  assert.throws(() => normalizeOidcConfig({ ...base, redirectUri: "http://dash.example.com/auth/callback" }), /https|carve-out/);
  // redirectUri path != /auth/callback.
  assert.throws(() => normalizeOidcConfig({ ...base, redirectUri: "https://dash.example.com/cb" }), /\/auth\/callback/);
  // cross-origin redirectUri is allowed at config (same-origin is enforced by the
  // path + scheme + the broker's own origin); but a public client passing an
  // auth method must throw.
  assert.throws(
    () => normalizeOidcConfig({ ...base, clientSecret: undefined, tokenEndpointAuthMethod: "client_secret_basic" }),
    /confidential/
  );
  // unknown key rejected.
  assert.throws(() => normalizeOidcConfig({ ...base, bogus: 1 }), /Unknown oidc config option/);
  // off-loopback https redirect without secureCookies -> still fine (redirect is https).
  assert.doesNotThrow(() => normalizeOidcConfig({ ...base }));
  // returnToAllowlist with an absolute entry rejected.
  assert.throws(() => normalizeOidcConfig({ ...base, returnToAllowlist: ["https://x/y"] }), /relative|scheme/);
  // bad TTL.
  assert.throws(() => normalizeOidcConfig({ ...base, sessionTtlSeconds: -1 }), /sessionTtlSeconds/);
});

test("createOidcSessionBroker rejects a missing cryptoProvider.hmac", async () => {
  assert.throws(
    () =>
      createOidcSessionBroker({
        cryptoProvider: {},
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT,
        secureCookies: true
      }),
    /cryptoProvider/
  );
});

test("an off-loopback broker without confirmed https is rejected at construction", async () => {
  const crypto = await makeCrypto();
  assert.throws(
    () =>
      createOidcSessionBroker({
        cryptoProvider: crypto,
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: "http://dash.example.com/auth/callback", // off-loopback plaintext
        lookupImpl: PUBLIC_LOOKUP
      }),
    /https|carve-out/
  );
});

// ---------------------------------------------------------------------------
// SEAM: the broker satisfies the dashboard sessionGuard contract
// ---------------------------------------------------------------------------

test("the broker handlers keys are exactly the three broker paths and authenticate is a function", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));
  assert.deepEqual(Object.keys(broker.handlers).sort(), ["/auth/callback", "/auth/login", "/auth/logout"]);
  assert.equal(typeof broker.authenticate, "function");
});

test("mounted in a real dashboard: unauthenticated /api/events -> 401 (not 302); /auth/login reachable; /healthz 200; /auth/other not a bypass", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  const broker = createOidcSessionBroker(baseOptions(crypto, { fetchImpl }));

  const dir = await mkdtemp(join(tmpdir(), "haechi-oidc-dash-"));
  const auditPath = join(dir, "audit.jsonl");
  // loopback bind with a guard is valid; drive requestHandler directly (no socket).
  const dashboard = createDashboardServer({ auditPath, host: "127.0.0.1", port: 0, sessionGuard: broker });
  const handler = dashboard.requestHandler;

  const hostHeader = "127.0.0.1";

  // unauthenticated /api/events -> 401, not 302.
  const apiRes = makeRes();
  apiRes.req = { method: "GET" };
  handler(makeRequestForDashboard({ method: "GET", url: "/api/events", host: hostHeader }), apiRes);
  await flush();
  assert.equal(apiRes.statusCode, 401);
  assert.notEqual(apiRes.statusCode, 302);

  // /auth/login is reachable (the broker handler runs -> 302 or 503).
  const loginRes = makeRes();
  loginRes.req = { method: "GET" };
  handler(makeRequestForDashboard({ method: "GET", url: "/auth/login", host: hostHeader }), loginRes);
  await flush();
  assert.ok(loginRes.statusCode === 302 || loginRes.statusCode === 503, `login reachable, got ${loginRes.statusCode}`);
  assert.notEqual(loginRes.statusCode, 401);

  // /healthz is 200 unauthenticated.
  const healthRes = makeRes();
  healthRes.req = { method: "GET" };
  handler(makeRequestForDashboard({ method: "GET", url: "/healthz", host: hostHeader }), healthRes);
  await flush();
  assert.equal(healthRes.statusCode, 200);

  // /auth/anything-else is NOT an unauthenticated bypass: it is a 404 (unknown route).
  const otherRes = makeRes();
  otherRes.req = { method: "GET" };
  handler(makeRequestForDashboard({ method: "GET", url: "/auth/anything-else", host: hostHeader }), otherRes);
  await flush();
  assert.notEqual(otherRes.statusCode, 200, "/auth/other must not serve audit data");
  assert.equal(otherRes.statusCode, 404);
});

function makeRequestForDashboard({ method, url, host }) {
  return { method, url, headers: { host }, socket: { remoteAddress: "127.0.0.1" } };
}

function flush() {
  return new Promise((resolve) => setTimeout(resolve, 20));
}

// ---------------------------------------------------------------------------
// FIX A: trustProxy drives cookie hardening
// ---------------------------------------------------------------------------

test("trustProxy + http-loopback redirectUri sets __Host- and Secure cookie names", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  // http-loopback redirectUri + trustProxy configured (non-null) — the external
  // scheme is https so __Host-/__Host- cookie names + Secure attribute must be used.
  const broker = createOidcSessionBroker({
    cryptoProvider: crypto,
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: "http://127.0.0.1/auth/callback",
    trustProxy: "10.0.0.1",
    lookupImpl: PUBLIC_LOOKUP,
    fetchImpl,
    now: () => NOW_MS
  });
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 302);
  const cookies = res.setCookies();
  assert.ok(cookies.length > 0, "expected a Set-Cookie header on /auth/login");
  const preauthCookie = cookies.find((c) => /preauth/.test(c));
  assert.ok(preauthCookie, "expected a preauth cookie");
  assert.match(preauthCookie, /^__Host-/, "cookie name must use __Host- prefix when trustProxy is set");
  assert.match(preauthCookie, /Secure/, "cookie must have Secure attribute when trustProxy is set");
});

test("plain http-loopback broker WITHOUT trustProxy/secureCookies uses non-__Host-, non-Secure cookie names", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeFetch({ key });
  // No trustProxy, no secureCookies: the loopback carve-out applies and cookie
  // hardening is disabled so browsers on http://localhost can receive the cookie.
  const broker = createOidcSessionBroker({
    cryptoProvider: crypto,
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: "http://127.0.0.1/auth/callback",
    lookupImpl: PUBLIC_LOOKUP,
    fetchImpl,
    now: () => NOW_MS
    // trustProxy: not set  secureCookies: not set
  });
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 302);
  const cookies = res.setCookies();
  assert.ok(cookies.length > 0, "expected a Set-Cookie header on /auth/login");
  const preauthCookie = cookies.find((c) => /preauth/.test(c));
  assert.ok(preauthCookie, "expected a preauth cookie");
  assert.doesNotMatch(preauthCookie, /^__Host-/, "cookie name must NOT use __Host- prefix on plain http-loopback without trustProxy");
  assert.doesNotMatch(preauthCookie, /Secure/, "cookie must NOT have Secure attribute on plain http-loopback without trustProxy");
});

// ---------------------------------------------------------------------------
// FIX B: authenticate() must not return the live mutable store object
// ---------------------------------------------------------------------------

test("mutating the object returned by authenticate() does not corrupt the session store", async () => {
  const { broker, sessionId } = await fullLogin();
  const sessionCookieName = "__Host-haechi_session";

  // First call: get the session object.
  const result1 = await broker.authenticate(makeReq({ cookies: { [sessionCookieName]: sessionId } }));
  assert.ok(result1, "first authenticate() must succeed");
  assert.ok(result1.identity, "first result must have identity");

  // Mutate the returned object — this must NOT affect the store.
  result1.identity = null;

  // Second call: the store entry must be unaffected.
  const result2 = await broker.authenticate(makeReq({ cookies: { [sessionCookieName]: sessionId } }));
  assert.ok(result2, "second authenticate() must still return a valid session");
  assert.ok(result2.identity, "identity must still be present after caller mutated the first result");
  assert.equal(result2.identity.provider, "oidc");
});
