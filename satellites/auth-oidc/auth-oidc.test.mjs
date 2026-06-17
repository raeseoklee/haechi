import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createLocalCryptoProvider, initLocalKeyFile } from "haechi/crypto";
import { createDashboardServer } from "haechi-dashboard";
import { createOidcSessionBroker, normalizeOidcConfig, createInMemorySessionStore } from "./index.mjs";

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

  // ASYNC sessionStore rejected fail-closed (a Promise-returning get() would make
  // a truthy Promise look like a valid session — a fail-OPEN). Both an async fn
  // and a plain fn returning a Promise are caught by the construction sync-probe.
  const asyncFnStore = { async get() { return null; }, set() {}, delete() {} };
  assert.throws(() => normalizeOidcConfig({ ...base, sessionStore: asyncFnStore }), /SYNCHRONOUS|thenable/);
  const promiseReturningStore = { get() { return Promise.resolve(null); }, set() {}, delete() {} };
  assert.throws(() => normalizeOidcConfig({ ...base, sessionStore: promiseReturningStore }), /SYNCHRONOUS|thenable/);
  // a missing method is still rejected; a SYNC store is accepted.
  assert.throws(() => normalizeOidcConfig({ ...base, sessionStore: { get() {}, set() {} } }), /get\/set\/delete/);
  assert.doesNotThrow(() => normalizeOidcConfig({ ...base, sessionStore: createInMemorySessionStore() }));
});

test("authenticate fails closed if a sessionStore.get somehow returns a thenable (no fail-open)", async () => {
  const crypto = await makeCrypto();
  // A "sneaky" store: returns null (sync) for the construction probe so it passes,
  // but a Promise for a real session id at authenticate time. The runtime guard
  // must treat that thenable as NO session (return null) — never a truthy
  // authenticated session (which the dashboard's truthy check would open /api/* on).
  const PROBE = "__haechi_sessionstore_sync_probe__";
  const sneaky = {
    get(id) { return id === PROBE ? null : Promise.resolve({ identity: {}, createdAt: 0, lastSeen: 0 }); },
    set() {},
    delete() {}
  };
  const broker = createOidcSessionBroker(baseOptions(crypto, {
    fetchImpl: async () => { throw new Error("no network"); },
    sessionStore: sneaky
  }));
  const session = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": "anything" } }));
  assert.equal(session, null, "a thenable from sessionStore.get must NOT authenticate (fail closed)");
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

// ---------------------------------------------------------------------------
// PR-2: trustedEndpointHosts — operator-pinned custom-domain allowlist
// (P1-SEC-026 residual). Symmetric with PR-1's createJwtVerifier option.
//
// Custom-domain IdP shape (Azure AD B2C / Auth0 custom domain): the issuer is
// on one host but the discovered endpoints live on another. Default (no
// allowlist) MUST stay byte-behavior-identical single-origin; the SSRF and
// issuer-confusion guards MUST stand regardless of the allowlist.
// ---------------------------------------------------------------------------

const CD_ISSUER = "https://login.contoso.com";
const CD_ENDPOINT_HOST = "contoso.b2clogin.com";
const CD_AUTHZ = "https://contoso.b2clogin.com/authorize";
const CD_TOKEN = "https://contoso.b2clogin.com/oauth/token";
const CD_JWKS = "https://contoso.b2clogin.com/.well-known/jwks.json";
const CD_END_SESSION = "https://contoso.b2clogin.com/logout";

function customDomainDiscovery(overrides = {}) {
  return {
    issuer: CD_ISSUER,
    authorization_endpoint: CD_AUTHZ,
    token_endpoint: CD_TOKEN,
    jwks_uri: CD_JWKS,
    end_session_endpoint: CD_END_SESSION,
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    ...overrides
  };
}

// A fetch stub for the custom-domain shape: discovery is served from the ISSUER
// host's .well-known; jwks + token are served from the custom-domain endpoint host.
function makeCustomDomainFetch({ key, discovery, idTokenBuilder, tokenStatus = 200 } = {}) {
  const disc = discovery ?? customDomainDiscovery();
  const calls = { discovery: 0, jwks: 0, token: 0, urls: [] };
  const fetchImpl = async (url) => {
    const u = String(url);
    calls.urls.push(u);
    if (u.endsWith("/.well-known/openid-configuration")) {
      calls.discovery += 1;
      return new Response(JSON.stringify(disc), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === disc.jwks_uri || u === CD_JWKS) {
      calls.jwks += 1;
      return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === disc.token_endpoint || u === CD_TOKEN) {
      calls.token += 1;
      const idToken = idTokenBuilder ? idTokenBuilder({ key }) : signIdToken({ claims: idClaims({ iss: CD_ISSUER }), privateKey: key.rsa.privateKey });
      return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS-TOK", token_type: "Bearer" }), {
        status: tokenStatus,
        headers: { "content-type": "application/json" }
      });
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };
  return { fetchImpl, calls };
}

const customDomainOptions = (crypto, overrides = {}) => ({
  cryptoProvider: crypto,
  issuer: CD_ISSUER,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT,
  scopes: ["openid", "profile"],
  secureCookies: true,
  lookupImpl: PUBLIC_LOOKUP,
  now: () => NOW_MS,
  ...overrides
});

// (a) DEFAULT: a discovery doc whose endpoints are on a DIFFERENT host than the
// issuer STILL throws when trustedEndpointHosts is unset (single-origin preserved).
test("PR-2 (a) DEFAULT: cross-host discovered endpoints still reject when trustedEndpointHosts is unset", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl } = makeCustomDomainFetch({ key }); // endpoints on contoso.b2clogin.com
  const broker = createOidcSessionBroker(customDomainOptions(crypto, { fetchImpl })); // no trustedEndpointHosts
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503, "single-origin must still reject a cross-host endpoint by default");
  assert.notEqual(res.statusCode, 302);
});

// (b) ALLOWLISTED: issuer login.contoso.com + endpoints on contoso.b2clogin.com
// with trustedEndpointHosts:[...] -> discovery succeeds and a full login/callback
// verifies (the JWKS on the custom host is accepted via the THREADED verifier option).
test("PR-2 (b) ALLOWLISTED: custom-domain discovery + full login/callback verifies (JWKS on the custom host accepted)", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  let capturedNonce = null;
  const { fetchImpl, calls } = makeCustomDomainFetch({
    key,
    idTokenBuilder: ({ key: k }) => signIdToken({ claims: idClaims({ iss: CD_ISSUER, nonce: capturedNonce }), privateKey: k.rsa.privateKey })
  });
  const broker = createOidcSessionBroker(
    customDomainOptions(crypto, { fetchImpl, auditSink: audit, trustedEndpointHosts: [CD_ENDPOINT_HOST] })
  );

  // login succeeds and the authorize URL is on the custom-domain endpoint host.
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  assert.equal(login.authUrl.origin + login.authUrl.pathname, CD_AUTHZ);

  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({
      url: `/auth/callback?code=AUTH_CODE&state=${encodeURIComponent(login.state)}`,
      cookies: { [login.preauthName]: login.preauthValue }
    }),
    cbRes
  );
  assert.equal(cbRes.statusCode, 302, "callback must succeed against a custom-domain JWKS host");
  assert.ok(calls.jwks > 0, "the verifier must have fetched the custom-host JWKS");
  const sessionCookie = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c));
  assert.ok(sessionCookie, "a session cookie must be minted");
  const sessionId = sessionCookie.split("=")[1].split(";")[0];
  const session = await broker.authenticate(makeReq({ cookies: { "__Host-haechi_session": sessionId } }));
  assert.ok(session, "session must authenticate");
  assert.equal(session.identity.provider, "oidc");
  assert.ok(audit.events.some((e) => e.type === "oidc.login.success"));
});

// (c) SSRF STILL ENFORCED: an allowlisted host that resolves to a BLOCKED address
// still fails closed at guardedFetch (post-DNS re-check), regardless of the allowlist.
test("PR-2 (c) SSRF STILL ENFORCED: an allowlisted host resolving to a blocked address fails closed at fetch", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const { fetchImpl, calls } = makeCustomDomainFetch({ key });
  // Discovery (issuer host) resolves public; the allowlisted endpoint host
  // resolves to the cloud metadata address -> guardedFetch must refuse.
  const lookupImpl = async (hostname) => {
    if (hostname === "login.contoso.com") return [{ address: "93.184.216.34", family: 4 }];
    if (hostname === CD_ENDPOINT_HOST) return [{ address: "169.254.169.254", family: 4 }];
    return [{ address: "93.184.216.34", family: 4 }];
  };
  const broker = createOidcSessionBroker(
    customDomainOptions(crypto, { fetchImpl, lookupImpl, trustedEndpointHosts: [CD_ENDPOINT_HOST] })
  );
  // login itself reaches authorize via discovery (issuer host, public) — discovery
  // succeeds, but the authorize/token endpoints sit on the blocked custom host.
  // The token exchange at /auth/callback must fail closed at guardedFetch.
  const login = await doLogin(broker);
  const before = calls.token;
  const res = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    res
  );
  assert.equal(res.statusCode, 401, "an allowlisted host resolving to metadata must still deny");
  assert.equal(calls.token, before, "the token POST must never reach the blocked host (SSRF re-check)");
});

// (d) ISSUER-CONFUSION STILL ENFORCED: a discovery doc whose metadata.issuer !=
// the configured issuer still throws EVEN IF its endpoint hosts are allowlisted.
test("PR-2 (d) ISSUER-CONFUSION STILL ENFORCED: metadata.issuer mismatch rejects even with allowlisted endpoint hosts", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  // endpoints on the allowlisted custom host, but metadata.issuer is a DIFFERENT issuer.
  const { fetchImpl } = makeCustomDomainFetch({ key, discovery: customDomainDiscovery({ issuer: "https://evil.contoso.com" }) });
  const broker = createOidcSessionBroker(
    customDomainOptions(crypto, { fetchImpl, trustedEndpointHosts: [CD_ENDPOINT_HOST] })
  );
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503, "an issuer-confusion mismatch must reject regardless of the endpoint-host allowlist");
});

// (e) A NON-ALLOWLISTED endpoint host still throws (the allowlist is exact, not
// a wildcard): allowlisting one custom host does not admit another.
test("PR-2 (e) a non-allowlisted endpoint host still rejects", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  // token_endpoint moves to a host that is NOT in the allowlist.
  const { fetchImpl } = makeCustomDomainFetch({
    key,
    discovery: customDomainDiscovery({ token_endpoint: "https://other.b2clogin.com/oauth/token" })
  });
  const broker = createOidcSessionBroker(
    customDomainOptions(crypto, { fetchImpl, trustedEndpointHosts: [CD_ENDPOINT_HOST] })
  );
  const res = makeRes();
  await broker.handlers["/auth/login"](makeReq({ url: "/auth/login" }), res);
  assert.equal(res.statusCode, 503, "a host outside the operator-pinned allowlist must still be rejected");
});

// (f) trustedEndpointHosts validation: URL-shaped / port-bearing / non-string /
// whitespace entries throw at construction; an unknown key is still rejected.
test("PR-2 (f) trustedEndpointHosts validation is fail-closed; unknown-key rejection still works", async () => {
  const crypto = await makeCrypto();
  const base = customDomainOptions(crypto, {});
  delete base.lookupImpl;
  delete base.now;

  // Non-array.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: CD_ENDPOINT_HOST }), /trustedEndpointHosts.*must be an array/);
  // URL-shaped (scheme).
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: ["https://contoso.b2clogin.com"] }), /bare hostname/);
  // Path segment.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: ["contoso.b2clogin.com/jwks"] }), /bare hostname/);
  // Port.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: ["contoso.b2clogin.com:443"] }), /bare hostname/);
  // Whitespace.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: ["contoso b2clogin"] }), /bare hostname/);
  // Empty string.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: [""] }), /non-empty hostname/);
  // Non-string.
  assert.throws(() => normalizeOidcConfig({ ...base, trustedEndpointHosts: [123] }), /non-empty hostname/);
  // Unknown key still rejected (strict KNOWN_KEYS).
  assert.throws(() => normalizeOidcConfig({ ...base, bogusKey: 1 }), /Unknown oidc config option/);

  // Valid: a bare hostname normalizes (lowercased) and is exposed on the config.
  const cfg = normalizeOidcConfig({ ...base, trustedEndpointHosts: ["Contoso.B2CLogin.com"] });
  assert.deepEqual(cfg.trustedEndpointHosts, ["contoso.b2clogin.com"]);

  // Absent: default empty array (zero behavior change).
  const dflt = normalizeOidcConfig({ ...base });
  assert.deepEqual(dflt.trustedEndpointHosts, []);
});

// ---------------------------------------------------------------------------
// PR-3: opt-in refresh-token rotation / silent renewal.
//
// enableRefresh (default FALSE) is byte-behavior-identical to today. When true:
// offline_access is requested, a refresh_token is stored ONLY as ciphertext, and
// an ACTIVE session within the renewal window silently renews via the stored
// refresh token — bounded by an absolute hard ceiling (originalCreatedAt +
// refreshMaxLifetimeSeconds). A refresh failure fails closed (evict + re-login).
// SYNTHETIC tokens/keys; the token endpoint / JWKS / discovery are mocked.
// ---------------------------------------------------------------------------

// id-token claims relative to a given clock value (ms) so the verifier's exp/nbf
// checks pass against the advanced clock.
function idClaimsAt(clockMs, extra = {}) {
  const s = Math.floor(clockMs / 1000);
  return { iss: ISSUER, aud: CLIENT_ID, sub: "user-789", exp: s + 3600, nbf: s - 10, iat: s - 10, ...extra };
}

// A refresh-aware fetch stub. Dispatches by URL; at the token endpoint it reads
// the form body to distinguish the authorization_code exchange from a
// refresh_token grant. The refresh-grant id_token is built by refreshIdToken()
// (caller-controlled per call) and the response may carry a rotated refresh_token.
function makeRefreshFetch({ key, getClock, getNonce, refreshIdToken, refreshResponse, refreshStatus = 200 } = {}) {
  const calls = { discovery: 0, jwks: 0, exchange: 0, refresh: 0, refreshTokensSent: [], urls: [] };
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    calls.urls.push(u);
    if (u.endsWith("/.well-known/openid-configuration")) {
      calls.discovery += 1;
      return new Response(JSON.stringify(discoveryDoc()), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === JWKS) {
      calls.jwks += 1;
      return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === TOKEN) {
      const body = new URLSearchParams(String(init.body || ""));
      const grant = body.get("grant_type");
      if (grant === "refresh_token") {
        calls.refresh += 1;
        calls.refreshTokensSent.push(body.get("refresh_token"));
        if (refreshResponse) {
          return new Response(JSON.stringify(refreshResponse(calls.refresh)), { status: refreshStatus, headers: { "content-type": "application/json" } });
        }
        const idToken = refreshIdToken
          ? refreshIdToken({ key, clockMs: getClock(), n: calls.refresh })
          : signIdToken({ claims: idClaimsAt(getClock()), privateKey: key.rsa.privateKey });
        const resp = { id_token: idToken, access_token: `ACCESS-REFRESH-${calls.refresh}`, token_type: "Bearer" };
        return new Response(JSON.stringify(resp), { status: refreshStatus, headers: { "content-type": "application/json" } });
      }
      // authorization_code exchange.
      calls.exchange += 1;
      const idToken = signIdToken({ claims: idClaimsAt(getClock(), { nonce: getNonce() }), privateKey: key.rsa.privateKey });
      const resp = { id_token: idToken, access_token: "ACCESS-INITIAL", refresh_token: "REFRESH-INITIAL", token_type: "Bearer" };
      return new Response(JSON.stringify(resp), { status: 200, headers: { "content-type": "application/json" } });
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };
  return { fetchImpl, calls };
}

// Drive a full login+callback under enableRefresh, returning the broker, the
// session id, the live session store (to inspect the stored ciphertext), the
// audit sink, and the call tracker.
async function refreshLogin(overrides = {}) {
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  const sessionStore = createInMemorySessionStore();
  let clock = NOW_MS;
  let capturedNonce = null;
  const { fetchImpl, calls } = makeRefreshFetch({
    key,
    getClock: () => clock,
    getNonce: () => capturedNonce,
    ...overrides.fetchArgs
  });
  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      auditSink: audit,
      sessionStore,
      now: () => clock,
      enableRefresh: true,
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000,
      refreshMaxLifetimeSeconds: 5000,
      ...overrides.brokerOverrides
    })
  );
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
  return {
    broker,
    key,
    audit,
    calls,
    sessionStore,
    sessionId,
    cbRes,
    crypto,
    setClock: (v) => {
      clock = v;
    },
    getClock: () => clock
  };
}

const SESSION_COOKIE_NAME = "__Host-haechi_session";
const REFRESH_AAD = { domain: "haechi:oidc:refresh-token:v1" };

// (a) DEFAULT enableRefresh:false unchanged — offline_access still stripped,
// no refresh stored, session hard-expires at the absolute TTL (no renewal).
test("PR-3 (a) DEFAULT enableRefresh:false — offline_access stripped, no refresh stored, hard-expires at absolute TTL", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const sessionStore = createInMemorySessionStore();
  let clock = NOW_MS;
  let capturedNonce = null;
  const { fetchImpl, calls } = makeRefreshFetch({ key, getClock: () => clock, getNonce: () => capturedNonce });
  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      sessionStore,
      now: () => clock,
      scopes: ["openid", "profile", "offline_access"], // operator asks for it
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000
      // enableRefresh omitted -> false
    })
  );
  // offline_access STRIPPED from the authorize scope even though it was requested.
  const login = await doLogin(broker);
  capturedNonce = login.nonce;
  const scope = login.authUrl.searchParams.get("scope").split(" ");
  assert.ok(scope.includes("openid"));
  assert.ok(!scope.includes("offline_access"), "offline_access must be stripped when enableRefresh is false");

  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=AUTH_CODE&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    cbRes
  );
  const sessionId = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];
  // No refresh token stored on the session record.
  const stored = sessionStore.get(sessionId);
  assert.ok(stored, "session minted");
  assert.equal(stored.refreshTokenEnvelope, undefined, "no refresh token stored when disabled");
  assert.equal(stored.originalCreatedAt, undefined);
  assert.equal(stored.subject, undefined);

  // Within the absolute TTL: ok.
  assert.ok(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })));
  // Past the absolute TTL: hard-expires (no renewal), no refresh POST ever made.
  clock = NOW_MS + 1001 * 1000;
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null);
  assert.equal(calls.refresh, 0, "no refresh grant when disabled");
});

// (b) enableRefresh:true — a session within the renewal window silently renews;
// createdAt advances; the session survives past the original absolute TTL.
test("PR-3 (b) enableRefresh:true — silent renewal in the window advances createdAt and survives past the original absolute TTL", async () => {
  const ctx = await refreshLogin();
  const { broker, sessionId, sessionStore, calls } = ctx;
  assert.ok(sessionId, "session minted");

  // offline_access was requested on the authorize URL (verify via a fresh login
  // is unnecessary: the stored refresh token proves the round-trip). Stored as
  // ciphertext (asserted in test g). createdAt == NOW_MS initially.
  const before = sessionStore.get(sessionId);
  assert.equal(before.createdAt, NOW_MS);

  // Advance into the renewal window: ttl=1000s, window=250s -> renewAt at 750s.
  ctx.setClock(NOW_MS + 800 * 1000);
  const renewed = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.ok(renewed, "an in-window renewable session must silently renew, not 401");
  assert.equal(calls.refresh, 1, "exactly one refresh grant fired");
  // createdAt advanced to the refresh time (new absolute window).
  assert.equal(renewed.createdAt, NOW_MS + 800 * 1000, "createdAt resets to the refresh time");

  // The session now survives PAST the ORIGINAL absolute TTL (NOW_MS + 1000s).
  ctx.setClock(NOW_MS + 1100 * 1000); // beyond the original absolute expiry
  const stillAlive = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.ok(stillAlive, "the renewed session survives past the original absolute TTL");
  // A success refresh audit event was emitted (sessionIdHash only, no token).
  assert.ok(ctx.audit.events.some((e) => e.type === "oidc.session.refresh"), "a refresh success event must be emitted");
});

// (c) HARD CEILING — renewal is refused once past originalCreatedAt +
// refreshMaxLifetimeSeconds (session evicted, re-login). The ceiling is absolute:
// successive renewals keep advancing createdAt (a new 1000s absolute window each),
// but NO renewal may extend the session beyond originalCreatedAt + 5000s.
test("PR-3 (c) HARD CEILING — no refresh past originalCreatedAt + refreshMaxLifetimeSeconds (evict + re-login)", async () => {
  // ttl=1000s, window=250s (renewAt 750s into each window), ceiling=5000s.
  const ctx = await refreshLogin();
  const { broker, sessionId, calls } = ctx;

  // Step the clock in 800s increments (inside each successive renewal window:
  // 800 >= 750 and 800 < 1000) so each authenticate() renews and advances
  // createdAt to the current clock. After k renewals createdAt = NOW_MS + 800k·s.
  // Stay strictly below the ceiling (5000s) on every renewal: k = 1..5 lands
  // createdAt at 800,1600,2400,3200,4000 (< 5000) — all renew.
  let renews = 0;
  for (let k = 1; k <= 5; k += 1) {
    ctx.setClock(NOW_MS + 800 * k * 1000);
    const r = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
    assert.ok(r, `renewal ${k} must succeed (createdAt advances, still under the ceiling)`);
    renews += 1;
  }
  assert.equal(calls.refresh, renews, "each in-window, under-ceiling authenticate renewed once");
  // createdAt is now NOW_MS + 4000s -> renewAt=4750s, absoluteExpiry=5000s. Do one
  // more renewal (land at 4800s: in-window, still < the 5000s ceiling) to push
  // createdAt to 4800s so its NEXT window [5550s, 5800s] lies fully past the ceiling.
  ctx.setClock(NOW_MS + 4800 * 1000);
  assert.ok(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), "renew to push createdAt to 4800s");
  const refreshesBeforeCeiling = calls.refresh;

  // createdAt=4800s -> renewAt=5550s, absoluteExpiry=5800s. Land at 5600s: in the
  // renewal window (5600 >= 5550, 5600 < 5800) AND past the ceiling (5600 >=
  // originalCreatedAt + 5000s). The ceiling check (evaluated FIRST inside the
  // refresh) must refuse and evict — NO refresh grant fires.
  ctx.setClock(NOW_MS + 5600 * 1000);
  const denied = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.equal(denied, null, "no refresh may cross the hard lifetime ceiling");
  assert.equal(calls.refresh, refreshesBeforeCeiling, "no refresh grant fired past the ceiling");
  assert.ok(
    ctx.audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_ceiling"),
    "a refresh_ceiling evict event must be emitted"
  );
  // The session is gone (re-login required).
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null);
});

// (d) ROTATION — a rotated refresh_token replaces the stored one; the old
// ciphertext is gone.
test("PR-3 (d) ROTATION — a rotated refresh_token replaces the stored ciphertext (old one discarded)", async () => {
  // The refresh response carries BOTH a valid (signed) id_token and a NEW
  // refresh_token (RFC 6749 §10.4 rotation). Build a dedicated rotating stub
  // (refreshLogin's default stub does not rotate). The stub closes over its key.
  const crypto = await makeCrypto();
  const key = makeKey();
  const sessionStore = createInMemorySessionStore();
  let clock = NOW_MS;
  let nonce = null;
  const { fetchImpl, calls } = makeRefreshFetch({
    key,
    getClock: () => clock,
    getNonce: () => nonce,
    refreshResponse: (n) => ({
      id_token: signIdToken({ claims: idClaimsAt(clock), privateKey: key.rsa.privateKey }),
      access_token: `A${n}`,
      refresh_token: `ROTATED-${n}`,
      token_type: "Bearer"
    })
  });
  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      sessionStore,
      now: () => clock,
      enableRefresh: true,
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000,
      refreshMaxLifetimeSeconds: 5000
    })
  );
  const login = await doLogin(broker);
  nonce = login.nonce;
  const cbRes = makeRes();
  await broker.handlers["/auth/callback"](
    makeReq({ url: `/auth/callback?code=C&state=${encodeURIComponent(login.state)}`, cookies: { [login.preauthName]: login.preauthValue } }),
    cbRes
  );
  const sid = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];

  const envBefore = sessionStore.get(sid).refreshTokenEnvelope;
  const plainBefore = await crypto.decrypt({ envelope: envBefore, aad: REFRESH_AAD });
  assert.equal(plainBefore, "REFRESH-INITIAL", "the initial stored token decrypts to the initial refresh token");

  clock = NOW_MS + 800 * 1000; // renewal window
  assert.ok(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sid } })));
  assert.equal(calls.refresh, 1);
  const envAfter = sessionStore.get(sid).refreshTokenEnvelope;
  const plainAfter = await crypto.decrypt({ envelope: envAfter, aad: REFRESH_AAD });
  assert.equal(plainAfter, "ROTATED-1", "the stored ciphertext now decrypts to the rotated refresh token");
  assert.notEqual(JSON.stringify(envAfter), JSON.stringify(envBefore), "the stored envelope changed (old ciphertext discarded)");
});

// (e) ANTI-SWAP — a refresh whose new id_token has a different sub is rejected
// (evict + re-login).
test("PR-3 (e) ANTI-SWAP — a refresh returning a different sub is rejected (evict)", async () => {
  const ctx = await refreshLogin({
    fetchArgs: {
      refreshIdToken: ({ key, clockMs }) =>
        signIdToken({ claims: idClaimsAt(clockMs, { sub: "attacker-sub" }), privateKey: key.rsa.privateKey })
    }
  });
  const { broker, sessionId, calls } = ctx;
  ctx.setClock(NOW_MS + 800 * 1000);
  const denied = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.equal(denied, null, "a subject swap on refresh must be rejected (fail closed)");
  assert.equal(calls.refresh, 1, "the refresh grant was attempted once");
  assert.ok(
    ctx.audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_subject_mismatch"),
    "a refresh_subject_mismatch evict event must be emitted"
  );
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null, "session is gone");
});

// (f) FAIL-CLOSED — a refresh returning non-2xx OR an unverifiable id_token
// evicts the session (authenticate returns null).
test("PR-3 (f) FAIL-CLOSED — a non-2xx refresh evicts the session", async () => {
  const ctx = await refreshLogin({
    fetchArgs: { refreshStatus: 400, refreshResponse: () => ({ error: "invalid_grant" }) }
  });
  const { broker, sessionId } = ctx;
  ctx.setClock(NOW_MS + 800 * 1000);
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null, "a non-2xx refresh fails closed");
  assert.ok(ctx.audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_failed"));
  // No stale/extended session left behind.
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null);
});

test("PR-3 (f) FAIL-CLOSED — an unverifiable refresh id_token (bad signature) evicts the session", async () => {
  const ctx = await refreshLogin({
    fetchArgs: {
      // Sign the refresh id_token with an UNRELATED key -> verification fails.
      refreshIdToken: ({ clockMs }) => {
        const wrong = makeKey();
        return signIdToken({ claims: idClaimsAt(clockMs), privateKey: wrong.rsa.privateKey });
      }
    }
  });
  const { broker, sessionId } = ctx;
  ctx.setClock(NOW_MS + 800 * 1000);
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null, "an unverifiable refresh id_token fails closed");
  assert.ok(ctx.audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_token_invalid"));
});

// (g) NO-PLAINTEXT — the stored refresh field is ciphertext (not the raw token)
// and no emitted audit event contains the raw refresh/access/id token string.
test("PR-3 (g) NO-PLAINTEXT — refresh stored only as ciphertext; no token in any audit event", async () => {
  const ctx = await refreshLogin();
  const { sessionStore, sessionId, audit, crypto } = ctx;

  // Drive one renewal so a refresh-success event also exists.
  ctx.setClock(NOW_MS + 800 * 1000);
  await ctx.broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));

  const stored = sessionStore.get(sessionId);
  // The stored field is an AEAD envelope object, NOT the raw token string.
  assert.ok(stored.refreshTokenEnvelope && typeof stored.refreshTokenEnvelope === "object", "stored as an envelope object");
  const serialized = JSON.stringify(stored.refreshTokenEnvelope);
  assert.ok(!serialized.includes("REFRESH-INITIAL"), "the raw refresh token must not appear in the stored envelope");
  // It must round-trip back to the plaintext under the bound AAD (proves it is
  // ciphertext of the real token, not the token itself).
  const back = await crypto.decrypt({ envelope: stored.refreshTokenEnvelope, aad: REFRESH_AAD });
  assert.equal(back, "REFRESH-INITIAL");

  // No audit event contains any raw token (refresh/access/id) string.
  const hay = JSON.stringify(audit.events);
  for (const needle of ["REFRESH-INITIAL", "ACCESS-INITIAL", "ACCESS-REFRESH", "id_token", "refresh_token", "access_token", "user-789"]) {
    assert.ok(!hay.includes(needle), `audit must not leak "${needle}"`);
  }
  // The audit allowlist still holds for the refresh event.
  const allowed = new Set(["type", "provider", "timestamp", "subjectHash", "issuerHash", "sessionIdHash", "reasonCode"]);
  for (const e of audit.events) {
    for (const k of Object.keys(e)) assert.ok(allowed.has(k), `unexpected audit field ${k} in ${e.type}`);
  }
});

// (h) config validation for enableRefresh / refreshMaxLifetimeSeconds; unknown
// key rejection intact; enableRefresh requires encrypt/decrypt.
test("PR-3 (h) config validation — enableRefresh + refreshMaxLifetimeSeconds fail-closed; unknown-key rejection intact", async () => {
  const crypto = await makeCrypto();
  const base = baseOptions(crypto, {});
  delete base.lookupImpl;
  delete base.now;

  // enableRefresh must be a boolean.
  assert.throws(() => normalizeOidcConfig({ ...base, enableRefresh: "yes" }), /enableRefresh.*boolean/);
  assert.throws(() => normalizeOidcConfig({ ...base, enableRefresh: 1 }), /enableRefresh.*boolean/);

  // refreshMaxLifetimeSeconds bounds (positive int within [1, MAX_TTL_SECONDS]).
  assert.throws(() => normalizeOidcConfig({ ...base, refreshMaxLifetimeSeconds: 0 }), /refreshMaxLifetimeSeconds/);
  assert.throws(() => normalizeOidcConfig({ ...base, refreshMaxLifetimeSeconds: -1 }), /refreshMaxLifetimeSeconds/);
  assert.throws(() => normalizeOidcConfig({ ...base, refreshMaxLifetimeSeconds: 1.5 }), /refreshMaxLifetimeSeconds/);
  assert.throws(() => normalizeOidcConfig({ ...base, refreshMaxLifetimeSeconds: 31 * 24 * 60 * 60 }), /refreshMaxLifetimeSeconds/);

  // Unknown key still rejected (strict KNOWN_KEYS).
  assert.throws(() => normalizeOidcConfig({ ...base, refreshBogus: 1 }), /Unknown oidc config option/);

  // Defaults: enableRefresh false, a 7-day ceiling exposed on the config.
  const dflt = normalizeOidcConfig({ ...base });
  assert.equal(dflt.enableRefresh, false);
  assert.equal(dflt.refreshMaxLifetimeSeconds, 7 * 24 * 60 * 60);

  // Valid opt-in: exposed on the normalized config.
  const cfg = normalizeOidcConfig({ ...base, enableRefresh: true, refreshMaxLifetimeSeconds: 3600 });
  assert.equal(cfg.enableRefresh, true);
  assert.equal(cfg.refreshMaxLifetimeSeconds, 3600);

  // enableRefresh requires a cryptoProvider with encrypt/decrypt (an hmac-only
  // provider is rejected — refresh tokens must be stored as ciphertext).
  const hmacOnly = { hmac: async () => "deadbeef".repeat(8) };
  assert.throws(
    () => normalizeOidcConfig({ ...base, cryptoProvider: hmacOnly, enableRefresh: true }),
    /encrypt.*decrypt|enableRefresh.*encrypt/
  );
  // hmac-only is fine when refresh is disabled.
  assert.doesNotThrow(() => normalizeOidcConfig({ ...base, cryptoProvider: hmacOnly, enableRefresh: false }));

  // enableRefresh:true forces offline_access into the authorize scope.
  const withRefresh = normalizeOidcConfig({ ...base, enableRefresh: true, scopes: ["openid", "profile"] });
  assert.ok(withRefresh.scopes.includes("offline_access"), "offline_access must be force-included when enableRefresh is true");
});

// LOGOUT drops the stored refresh token (deleting the session entry suffices).
test("PR-3 logout drops the stored refresh token (session record + its ciphertext gone)", async () => {
  const ctx = await refreshLogin();
  const { broker, sessionId, sessionStore } = ctx;
  assert.ok(sessionStore.get(sessionId)?.refreshTokenEnvelope, "a refresh envelope was stored");
  const res = makeRes();
  await broker.handlers["/auth/logout"](
    makeReq({ method: "POST", url: "/auth/logout", cookies: { [SESSION_COOKIE_NAME]: sessionId }, headers: { "x-haechi-csrf": "1" } }),
    res
  );
  assert.ok(res.statusCode === 200 || res.statusCode === 302);
  assert.equal(sessionStore.get(sessionId), null, "the session record (and its stored refresh ciphertext) is gone after logout");
  assert.equal(await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })), null);
});

// SINGLE-FLIGHT — concurrent in-window authenticate() calls share ONE refresh.
test("PR-3 single-flight — concurrent in-window authenticate() calls fire exactly ONE refresh grant", async () => {
  const ctx = await refreshLogin();
  const { broker, sessionId, calls } = ctx;
  ctx.setClock(NOW_MS + 800 * 1000);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } })))
  );
  assert.ok(results.every((r) => r && r.identity), "every concurrent caller gets the renewed session");
  assert.equal(calls.refresh, 1, "single-flight collapses concurrent refreshes into one token-endpoint POST");
});

// ---------------------------------------------------------------------------
// PR-3 PRE-PUBLISH REVIEW REGRESSIONS — lock in the two 0.2.0 refresh fixes.
//
// These tests reproduce two issues found in a pre-publish review of the
// (unreleased) auth-oidc 0.2.0 refresh feature; both are now FIXED in
// index.mjs. Each test FAILS against the pre-fix code and PASSES against the
// fixed code:
//   A. HIGH resurrection race — a logout that deletes the session DURING the
//      refresh network wait must NOT be undone by the post-refresh commit.
//      Pre-fix: performRefresh ran an UNCONDITIONAL sessionStore.set() at the
//      end, silently resurrecting the logged-out session. Fixed: a synchronous
//      get-then-check resurrection guard (live + matching gen) before the set.
//   B. MEDIUM raw-sub-at-rest — the session must NOT persist the raw `sub`.
//      Pre-fix: stored session.subject = claims.sub (PII at rest in any custom
//      Redis/DB sessionStore). Fixed: anti-swap rebuilds the identity from the
//      renewed claims and compares the keyed-HMAC subjectHash; the raw sub is
//      never stored.
//   C. ANTI-SWAP SAME-SUB STILL RENEWS — guard the happy path of the HMAC
//      compare (a SAME-sub refresh must still renew; the HMAC compare must not
//      break a legitimate renewal).
// SYNTHETIC issuers/subjects/keys; token endpoint / JWKS / discovery mocked.
// ---------------------------------------------------------------------------

// (A) RESURRECTION RACE. Drive a renewable login, advance into the renewal
// window, then trigger renewal via authenticate() while the mocked refresh
// token-endpoint fetch INTERLEAVES a logout for the SAME session before it
// resolves — deleting it from the sessionStore mid-flight. After authenticate()
// resolves: (i) it returned null (the refresh did NOT resurrect the session),
// and (ii) a subsequent authenticate() with the same cookie also returns null
// (the session is truly gone, never re-saved by the post-refresh commit).
//
// PRE-FIX: performRefresh's final, UNCONDITIONAL sessionStore.set(sessionId,
// session) would re-add the just-deleted session, so authenticate() returns the
// renewed session (non-null) AND the follow-up call also returns it — both
// assertions below would FAIL. The synchronous resurrection guard makes them PASS.
test("PR-3 RESURRECTION RACE — a logout DURING the refresh network wait is NOT undone by the post-refresh commit", async () => {
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  const sessionStore = createInMemorySessionStore();
  let clock = NOW_MS;
  let capturedNonce = null;

  // Late-bound holders so the refresh-grant fetch branch can reach the broker +
  // the live session id to interleave a logout mid-flight (the broker/sessionId
  // do not exist yet when the fetch closure is created).
  let brokerRef = null;
  let sessionIdRef = null;
  let interleavedLogout = 0;

  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify(discoveryDoc()), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === JWKS) {
      return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === TOKEN) {
      const body = new URLSearchParams(String(init.body || ""));
      if (body.get("grant_type") === "refresh_token") {
        // INTERLEAVE: a concurrent logout for the SAME session lands DURING the
        // refresh network wait. Drive it through the broker's own logout handler
        // (POST + CSRF header + the session cookie) so the session id is deleted
        // from the injected sessionStore BEFORE this fetch resolves.
        interleavedLogout += 1;
        const logoutRes = makeRes();
        await brokerRef.handlers["/auth/logout"](
          makeReq({
            method: "POST",
            url: "/auth/logout",
            cookies: { [SESSION_COOKIE_NAME]: sessionIdRef },
            headers: { "x-haechi-csrf": "1" }
          }),
          logoutRes
        );
        // The session is now gone from the store; THEN return a valid refresh
        // response (same sub -> anti-swap would otherwise pass and re-commit).
        const idToken = signIdToken({ claims: idClaimsAt(clock), privateKey: key.rsa.privateKey });
        return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS-REFRESH-1", token_type: "Bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      // authorization_code exchange (mints the renewable session).
      const idToken = signIdToken({ claims: idClaimsAt(clock, { nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(
        JSON.stringify({ id_token: idToken, access_token: "ACCESS-INITIAL", refresh_token: "REFRESH-INITIAL", token_type: "Bearer" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };

  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      auditSink: audit,
      sessionStore,
      now: () => clock,
      enableRefresh: true,
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000,
      refreshMaxLifetimeSeconds: 5000
    })
  );
  brokerRef = broker;

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
  const sessionId = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];
  sessionIdRef = sessionId;
  assert.ok(sessionStore.get(sessionId), "a renewable session was minted");

  // Advance into the renewal window (ttl=1000s, window=250s -> renewAt 750s).
  clock = NOW_MS + 800 * 1000;

  // Trigger the silent renewal. The mocked refresh fetch deletes this very
  // session mid-flight (above), so the post-refresh commit must NOT resurrect it.
  const renewed = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));

  // (i) authenticate() returned null — the refresh did not resurrect a session
  //     deleted during the network wait.
  assert.equal(interleavedLogout, 1, "the refresh fetch interleaved exactly one logout for the same session");
  assert.equal(renewed, null, "a logout during the refresh network wait must NOT be undone (no resurrection)");

  // (ii) the session is truly gone from the store (never re-saved).
  assert.equal(sessionStore.get(sessionId), null, "the logged-out session must not be re-added by the refresh commit");

  // (iii) a subsequent authenticate() with the same cookie also returns null.
  const after = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.equal(after, null, "replaying the cookie after the raced logout must still deny");
});

// (B) NO RAW SUB AT REST. Use an email-shaped synthetic subject and
// enableRefresh; complete a login that stores a refresh-capable session; then
// inspect the STORED session record (a sessionStore that captures the object
// passed to set()) and assert NO field contains the raw subject string
// (deep-scan the stored record JSON), while session.identity.subjectHash IS
// present. Also assert anti-swap still works (a refresh with a DIFFERENT sub is
// rejected / the session is evicted).
//
// PRE-FIX: the callback stored session.subject = claims.sub, so the raw
// "alice@corp.example" WOULD appear in the deep-scanned stored-record JSON —
// the no-raw-sub assertion would FAIL. The fixed code never persists the raw
// sub (anti-swap uses the keyed-HMAC subjectHash), so the scan finds nothing.
test("PR-3 NO RAW SUB AT REST — the stored session record never contains the raw sub; anti-swap still rejects a swapped sub", async () => {
  const RAW_SUB = "alice@corp.example";
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();

  // A capturing sessionStore: wraps the in-memory store and records the EXACT
  // object handed to set() so we inspect what would be persisted at rest.
  const inner = createInMemorySessionStore();
  const setCaptures = [];
  const sessionStore = {
    set(id, session) {
      setCaptures.push({ id, session });
      return inner.set(id, session);
    },
    get(id) {
      return inner.get(id);
    },
    delete(id) {
      return inner.delete(id);
    },
    size() {
      return inner.size();
    }
  };

  let clock = NOW_MS;
  let capturedNonce = null;
  // Control the refresh-grant sub independently: by default the refresh returns
  // a DIFFERENT sub ("attacker-sub") so the anti-swap assertion below bites.
  let refreshSub = "attacker-sub";

  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify(discoveryDoc()), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === JWKS) {
      return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === TOKEN) {
      const body = new URLSearchParams(String(init.body || ""));
      if (body.get("grant_type") === "refresh_token") {
        const idToken = signIdToken({ claims: idClaimsAt(clock, { sub: refreshSub }), privateKey: key.rsa.privateKey });
        return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS-REFRESH", token_type: "Bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      const idToken = signIdToken({ claims: idClaimsAt(clock, { sub: RAW_SUB, nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(
        JSON.stringify({ id_token: idToken, access_token: "ACCESS-INITIAL", refresh_token: "REFRESH-INITIAL", token_type: "Bearer" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };

  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      auditSink: audit,
      sessionStore,
      now: () => clock,
      enableRefresh: true,
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000,
      refreshMaxLifetimeSeconds: 5000
    })
  );

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
  const sessionId = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];

  const stored = sessionStore.get(sessionId);
  assert.ok(stored, "a refresh-capable session was minted");
  assert.ok(stored.refreshTokenEnvelope, "the session is renewable (refresh ciphertext stored)");

  // The keyed-HMAC subjectHash IS present (the anti-swap pin) ...
  assert.ok(stored.identity && typeof stored.identity.subjectHash === "string" && stored.identity.subjectHash.length > 0,
    "the session identity must carry a keyed-HMAC subjectHash");
  assert.match(stored.identity.subjectHash, /^[a-f0-9]{64}$/);

  // ... and the RAW sub appears NOWHERE in the stored record (deep-scan the
  // captured + the live stored object JSON). There is no top-level
  // session.subject field, and no nested value equals the raw sub.
  assert.equal(stored.subject, undefined, "the session must not carry a top-level raw `subject` field");
  const storedJson = JSON.stringify(stored);
  assert.ok(!storedJson.includes(RAW_SUB), "the raw sub must not appear anywhere in the live stored session record");
  for (const cap of setCaptures) {
    assert.ok(!JSON.stringify(cap.session).includes(RAW_SUB), "the raw sub must not appear in any object handed to sessionStore.set()");
  }

  // Anti-swap STILL works: the refresh returns a DIFFERENT sub -> evict + null.
  clock = NOW_MS + 800 * 1000; // renewal window
  const denied = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.equal(denied, null, "a refresh returning a different sub must be rejected (anti-swap via keyed-HMAC compare)");
  assert.ok(
    audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_subject_mismatch"),
    "a refresh_subject_mismatch evict event must be emitted"
  );
  assert.equal(sessionStore.get(sessionId), null, "the session is evicted after the subject swap");
});

// (C) ANTI-SWAP SAME-SUB STILL RENEWS. A refresh that returns the SAME sub as
// the pinned session renews successfully (the keyed-HMAC subjectHash compare
// matches). This guards against the HMAC compare accidentally breaking the
// happy path: with no raw sub stored, a legitimate same-sub renewal must still
// reconstruct an identical subjectHash and renew, NOT fail closed.
test("PR-3 ANTI-SWAP SAME-SUB — a refresh returning the SAME sub renews (the keyed-HMAC compare matches the happy path)", async () => {
  const RAW_SUB = "alice@corp.example";
  const crypto = await makeCrypto();
  const key = makeKey();
  const audit = makeAuditSink();
  const sessionStore = createInMemorySessionStore();
  let clock = NOW_MS;
  let capturedNonce = null;

  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    if (u.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify(discoveryDoc()), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === JWKS) {
      return new Response(JSON.stringify({ keys: [key.jwk] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u === TOKEN) {
      const body = new URLSearchParams(String(init.body || ""));
      if (body.get("grant_type") === "refresh_token") {
        // SAME sub on the renewed id_token -> the keyed-HMAC subjectHash matches.
        const idToken = signIdToken({ claims: idClaimsAt(clock, { sub: RAW_SUB }), privateKey: key.rsa.privateKey });
        return new Response(JSON.stringify({ id_token: idToken, access_token: "ACCESS-REFRESH", token_type: "Bearer" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      const idToken = signIdToken({ claims: idClaimsAt(clock, { sub: RAW_SUB, nonce: capturedNonce }), privateKey: key.rsa.privateKey });
      return new Response(
        JSON.stringify({ id_token: idToken, access_token: "ACCESS-INITIAL", refresh_token: "REFRESH-INITIAL", token_type: "Bearer" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    throw new Error(`unexpected fetch URL: ${u}`);
  };

  const broker = createOidcSessionBroker(
    baseOptions(crypto, {
      fetchImpl,
      auditSink: audit,
      sessionStore,
      now: () => clock,
      enableRefresh: true,
      sessionTtlSeconds: 1000,
      idleTtlSeconds: 1000,
      refreshMaxLifetimeSeconds: 5000
    })
  );

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
  const sessionId = cbRes.setCookies().find((c) => /session/.test(c) && !/preauth/.test(c)).split("=")[1].split(";")[0];
  const pinnedHash = sessionStore.get(sessionId).identity.subjectHash;

  clock = NOW_MS + 800 * 1000; // renewal window
  const renewed = await broker.authenticate(makeReq({ cookies: { [SESSION_COOKIE_NAME]: sessionId } }));
  assert.ok(renewed, "a same-sub refresh must renew (the keyed-HMAC subjectHash compare matches)");
  assert.equal(renewed.createdAt, NOW_MS + 800 * 1000, "createdAt resets to the refresh time on a successful renewal");
  assert.equal(renewed.identity.subjectHash, pinnedHash, "the renewed identity keeps the same keyed-HMAC subjectHash");
  assert.ok(audit.events.some((e) => e.type === "oidc.session.refresh"), "a refresh success event must be emitted");
  // No subject-mismatch eviction on the happy path.
  assert.ok(
    !audit.events.some((e) => e.type === "oidc.session.evict" && e.reasonCode === "refresh_subject_mismatch"),
    "a same-sub renewal must NOT trigger a subject-mismatch eviction"
  );
  // The renewed live session still carries no raw sub and a present subjectHash.
  const live = sessionStore.get(sessionId);
  assert.ok(!JSON.stringify(live).includes(RAW_SUB), "the renewed stored record must still not contain the raw sub");
  assert.equal(live.identity.subjectHash, pinnedHash);
});
