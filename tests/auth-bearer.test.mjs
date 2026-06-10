import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRuntime, normalizeConfig } from "../packages/cli/runtime.mjs";
import { initLocalKeyFile, createLocalCryptoProvider } from "../packages/crypto/index.mjs";
import { addToken, createBearerAuthProvider, buildIdentity, buildExternalIdentity, readAuthStore } from "../packages/auth/index.mjs";

const CLI = fileURLToPath(new URL("../packages/cli/bin/haechi.mjs", import.meta.url));

function run(args, cwd) {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });
  return { ...result, json: result.stdout ? JSON.parse(result.stdout) : null };
}

async function setup(dir) {
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  return {
    keyFile,
    cryptoProvider: createLocalCryptoProvider({ keyFile }),
    storePath: join(dir, ".haechi", "auth.json")
  };
}

function bearerRequest(token) {
  return { headers: token ? { authorization: `Bearer ${token}` } : {} };
}

test("bearer provider authenticates a valid token into a PII-safe identity", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-"));
  const { cryptoProvider, storePath } = await setup(dir);
  const { token, record } = await addToken({
    path: storePath, cryptoProvider, type: "service", scopes: ["team:eng"], labels: { env: "prod" }
  });

  const provider = createBearerAuthProvider({ path: storePath, cryptoProvider });
  const identity = await provider.authenticate(bearerRequest(token));

  assert.equal(identity.id, record.id);
  assert.equal(identity.type, "service");
  assert.equal(identity.provider, "bearer");
  assert.deepEqual(identity.scopes, ["team:eng"]);
  assert.deepEqual(identity.labels, { env: "prod" });
  // PII-safe: subject/issuer are keyed HMAC hex digests, not raw values.
  assert.match(identity.subjectHash, /^[a-f0-9]{64}$/);
  assert.match(identity.issuerHash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(identity), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("bearer provider fails closed for missing, invalid, and revoked tokens", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-deny-"));
  const { cryptoProvider, storePath } = await setup(dir);
  const { token } = await addToken({ path: storePath, cryptoProvider, type: "user" });
  const provider = createBearerAuthProvider({ path: storePath, cryptoProvider });

  assert.equal(await provider.authenticate(bearerRequest(null)), null);
  assert.equal(await provider.authenticate(bearerRequest("hae_wrongtoken")), null);
  assert.equal(await provider.authenticate({ headers: { authorization: "Basic x" } }), null);

  const store = await readAuthStore(storePath);
  store.tokens[0].disabled = true;
  const { writeFile } = await import("node:fs/promises");
  await writeFile(storePath, JSON.stringify(store), "utf8");
  assert.equal(await provider.authenticate(bearerRequest(token)), null);
});

test("the token store keeps only a keyed hash, never the plaintext", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-store-"));
  const { cryptoProvider, storePath } = await setup(dir);
  const { token } = await addToken({ path: storePath, cryptoProvider, type: "agent" });

  const raw = await readFile(storePath, "utf8");
  assert.doesNotMatch(raw, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(raw, /"tokenHash"/);
});

test("addToken rejects disallowed label keys and invalid types", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-validate-"));
  const { cryptoProvider, storePath } = await setup(dir);

  await assert.rejects(() => addToken({ path: storePath, cryptoProvider, type: "robot" }), /Invalid token type/);
  await assert.rejects(
    () => addToken({ path: storePath, cryptoProvider, type: "user", labels: { ssn: "x" } }),
    /Label key not allowed/
  );
});

test("runtime wires the bearer provider and fails closed for external without injection", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-runtime-"));
  const { keyFile, storePath } = await setup(dir);
  const base = { keys: { keyFile }, audit: { path: join(dir, ".haechi", "audit.jsonl") } };

  const none = createRuntime({ ...base, auth: { provider: "none" } });
  assert.equal(none.authProvider, null);

  const bearer = createRuntime({ ...base, auth: { provider: "bearer", store: storePath } });
  assert.equal(typeof bearer.authProvider.authenticate, "function");

  assert.throws(() => createRuntime({ ...base, auth: { provider: "external" } }), /requires createRuntime/);

  const injected = { authenticate: async () => ({ id: "x", provider: "external" }) };
  const ext = createRuntime({ ...base, auth: { provider: "external" } }, { authProvider: injected });
  assert.equal(ext.authProvider, injected);
});

test("config validation covers the auth block", () => {
  assert.throws(() => normalizeConfig({ auth: { provider: "oauth" } }), /auth.provider/);
  assert.throws(() => normalizeConfig({ auth: { store: "" } }), /auth.store/);
  assert.throws(() => normalizeConfig({ auth: { allowedLabelKeys: [7] } }), /allowedLabelKeys/);
  const ok = normalizeConfig({ auth: { provider: "bearer" } });
  assert.equal(ok.auth.provider, "bearer");
  assert.deepEqual(ok.auth.allowedLabelKeys, ["team", "env", "tier", "role"]);
});

test("identity hashes are stable per subject and distinct across subjects", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-id-"));
  const { cryptoProvider } = await setup(dir);
  const a = await buildIdentity({ id: "tok_auth_a", type: "user", scopes: [], labels: {} }, cryptoProvider);
  const a2 = await buildIdentity({ id: "tok_auth_a", type: "user", scopes: [], labels: {} }, cryptoProvider);
  const b = await buildIdentity({ id: "tok_auth_b", type: "user", scopes: [], labels: {} }, cryptoProvider);
  assert.equal(a.subjectHash, a2.subjectHash);
  assert.notEqual(a.subjectHash, b.subjectHash);
  assert.equal(a.issuerHash, b.issuerHash);
});

test("auth CLI add/list/revoke round-trips without leaking the token", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-auth-cli-"));
  assert.equal(run(["init", "--force"], dir).status, 0);

  const add = run(["auth", "add", "--type", "service", "--scope", "team:eng", "--scope", "team:sec", "--label", "env=prod"], dir);
  assert.equal(add.status, 0);
  assert.match(add.json.token, /^hae_/);
  assert.deepEqual(add.json.scopes, ["team:eng", "team:sec"]);
  assert.equal(add.json.labels.env, "prod");

  const list = run(["auth", "list"], dir);
  const entry = list.json.tokens.find((t) => t.id === add.json.id);
  assert.ok(entry);
  assert.equal(entry.token, undefined);
  assert.equal(entry.tokenHash, undefined);

  const revoke = run(["auth", "revoke", add.json.id], dir);
  assert.equal(revoke.json.result.revoked, true);
  assert.equal(run(["auth", "list"], dir).json.tokens.find((t) => t.id === add.json.id).disabled, true);

  // The store file never contains the plaintext token.
  const raw = await readFile(join(dir, ".haechi", "auth.json"), "utf8");
  assert.doesNotMatch(raw, new RegExp(add.json.token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("buildExternalIdentity is PII-safe and fails closed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-extid-"));
  const keyFile = join(dir, ".haechi", "dev.keys.json");
  await initLocalKeyFile(keyFile, { force: true });
  const cryptoProvider = createLocalCryptoProvider({ keyFile });

  const id = await buildExternalIdentity(
    { provider: "jwt", subject: "user-42", issuer: "https://idp.example.com", type: "service", scopes: ["read"], labels: { team: "core" } },
    cryptoProvider
  );
  assert.equal(id.provider, "jwt");
  assert.equal(id.type, "service");
  assert.match(id.subjectHash, /^[a-f0-9]{64}$/);
  assert.match(id.issuerHash, /^[a-f0-9]{64}$/);
  assert.ok(id.id.startsWith("jwt:"));
  // no raw subject/issuer anywhere in the identity
  const s = JSON.stringify(id);
  assert.doesNotMatch(s, /user-42/);
  assert.doesNotMatch(s, /idp\.example\.com/);
  // same subject is stable; different subject differs
  const id2 = await buildExternalIdentity({ provider: "jwt", subject: "user-42", issuer: "https://idp.example.com" }, cryptoProvider);
  const id3 = await buildExternalIdentity({ provider: "jwt", subject: "other", issuer: "https://idp.example.com" }, cryptoProvider);
  assert.equal(id.subjectHash, id2.subjectHash);
  assert.notEqual(id.subjectHash, id3.subjectHash);

  // fail closed: missing hmac, empty subject/issuer, bad type, bad scopes, disallowed label
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "s", issuer: "i" }, {}), /hmac/);
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "", issuer: "i" }, cryptoProvider), /subject/);
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "s", issuer: "" }, cryptoProvider), /issuer/);
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "s", issuer: "i", type: "root" }, cryptoProvider), /type/);
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "s", issuer: "i", scopes: [1] }, cryptoProvider), /scopes/);
  await assert.rejects(() => buildExternalIdentity({ provider: "jwt", subject: "s", issuer: "i", labels: { secret: "x" } }, cryptoProvider), /Label key/);
});
