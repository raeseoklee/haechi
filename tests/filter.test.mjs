import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultFilterEngine, HARD_BLOCK_TYPES } from "../packages/filter/index.mjs";
import { collectStringEntries } from "../packages/core/index.mjs";
import { initLocalKeyFile, createLocalCryptoProvider } from "../packages/crypto/index.mjs";

test("default filter detects common PII and secrets", async () => {
  const filter = createDefaultFilterEngine();
  const payload = {
    message: "Email minji.kim@example.com, phone 010-1234-5678, token sk_demo_1234567890abcdef1234567890abcdef"
  };

  const detections = await filter.detect({ entries: collectStringEntries(payload), context: {} });
  const types = detections.map((detection) => detection.type).sort();

  assert.deepEqual(types, ["api_key", "email", "phone"]);
});

test("custom filter rule can be added without changing core", async () => {
  const filter = createDefaultFilterEngine({
    customRules: [
      {
        id: "internal-contract",
        type: "contract_id",
        pattern: "CT-[0-9]{6}",
        confidence: 0.8
      }
    ]
  });

  const detections = await filter.detect({
    entries: collectStringEntries({ message: "internal id CT-123456" }),
    context: {}
  });

  assert.equal(detections[0].type, "contract_id");
});

test("KR RRN detector requires checksum-valid synthetic values", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({
      valid: "synthetic 900101-1234568",
      invalid: "synthetic 900101-1234567"
    }),
    context: {}
  });

  assert.equal(detections.filter((detection) => detection.type === "kr_rrn").length, 1);
});

test("Haechi's own transform markers are never re-detected (no self-flagging)", async () => {
  const filter = createDefaultFilterEngine();
  // `[TOKEN:` reads like a `token:<secret>` assignment; without marker exclusion
  // Haechi would flag its own token as a `secret` (and block a tokenized
  // round-trip in response-enforce). The encrypt/redact markers must be inert too.
  const detections = await filter.detect({
    entries: collectStringEntries({
      tokenized: "please email [TOKEN:tok_email_a6d376389bb21964] today",
      // base64url of a faithful encrypt envelope ({v,alg,kid,iv,ct,tag,aadHash}) —
      // a GENUINE HAECHI_ENC marker. Markers are recognized by inner shape now, so
      // this must decode to a real envelope (kid+aadHash) to be skipped.
      encrypted: "value [HAECHI_ENC:eyJ2IjoxLCJhbGciOiJBMjU2R0NNIiwia2lkIjoiazEiLCJpdiI6IkFBQUFBQUFBQUFBQUFBQUEiLCJjdCI6IlpIVnRiWGsiLCJ0YWciOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwiYWFkSGFzaCI6ImFiYzEyMyJ9] here",
      redacted: "value [REDACTED:email] here"
    }),
    context: { direction: "response" }
  });
  assert.deepEqual(detections, []);
});

test("marker exclusion is response-only: a request can't smuggle a secret in a fake marker", async () => {
  const filter = createDefaultFilterEngine();
  // On the REQUEST direction (Haechi hasn't transformed anything yet), a
  // marker-shaped wrapper is NOT trusted — the real key inside is still detected.
  const detections = await filter.detect({
    entries: collectStringEntries({ evasion: "key is [TOKEN:sk_demo_0123456789abcdef01234567] hidden" }),
    context: { direction: "request" }
  });
  assert.ok(detections.some((d) => d.type === "api_key"), "request-side must still detect the wrapped key");
});

test("marker exclusion is positional: a real secret ADJACENT to a marker is still detected on the response", async () => {
  const filter = createDefaultFilterEngine();
  // The exclusion drops only detections that OVERLAP a marker span — a key that
  // merely sits next to a marker must still be caught, so a marker boundary
  // cannot be used to hide an adjacent secret the model leaks.
  const detections = await filter.detect({
    entries: collectStringEntries({
      glued: "[TOKEN:tok_abc]sk_demo_0123456789abcdef01234567",
      spaced: "[TOKEN:tok_abc] sk_demo_0123456789abcdef01234567"
    }),
    context: { direction: "response" }
  });
  assert.equal(detections.filter((d) => d.type === "api_key").length, 2);
});

// CR-???: the response-direction marker skip records a span only when the inner
// content matches a GENUINE format emitted by core (replacementFor). Before the
// tightening, the marker FRAME `[(?:TOKEN|…):[^\]]*]` skipped ANY inner content,
// so a hostile model could exfiltrate a real secret by wrapping it in a FAKE
// marker. All secrets below are SYNTHETIC (documented-shape fabrications).
const SYNTH_SECRET = "sk-ant-api03-EXAMPLE0123456789abcdefABCDEF"; // matches the anthropic-api-key rule (type secret)

test("response marker skip: a FAKE marker wrapping a real secret is NOW scanned (no exfiltration)", async () => {
  const filter = createDefaultFilterEngine();
  // A model can emit a marker-SHAPED string whose inner content is not a genuine
  // token/redaction/envelope. Each of these wraps a synthetic secret in an inner
  // form that fails the genuine check, so the span is NOT skipped and the secret
  // is detected.
  const cases = {
    fakeToken: `here is [TOKEN:${SYNTH_SECRET}] ok`,        // inner is neither a vault id nor <type>:<hex>
    fakeEnc: `here is [HAECHI_ENC:${SYNTH_SECRET}] ok`,     // inner is not base64url-of-envelope
    fakeRedacted: `here is [REDACTED:${SYNTH_SECRET}] ok`,  // inner is not a type-name
    fakeTokenTypeColon: `here is [TOKEN:secret:${SYNTH_SECRET}] ok` // <type>: prefix but inner is not pure hex
  };
  for (const [name, text] of Object.entries(cases)) {
    const detections = await filter.detect({
      entries: collectStringEntries({ leaked: text }),
      context: { direction: "response" }
    });
    assert.ok(
      detections.some((d) => d.type === "secret"),
      `fake marker (${name}) must be scanned and the wrapped secret detected`
    );
  }
});

test("response marker skip: a LOWERCASE-identifier-shaped secret can't hide in a genuine-shaped marker", async () => {
  // Regression for the residual the first tightening missed: a secret whose body
  // is a lowercase identifier (e.g. a GitHub gh[pousr]_ token) fits the genuine
  // type-name / token-type shapes, so a hostile model could smuggle it as the
  // <type> segment of an otherwise genuine-shaped marker. We use a CUSTOM `\b`-
  // anchored rule (no real provider token in the test) — the \b case also proves
  // the segment-isolation scan: in the vault form `tok_<secret>_<hex>` the secret
  // is glued to `tok_` (no word boundary), so it is only caught when the <type>
  // segment is scanned on its own.
  const filter = createDefaultFilterEngine({
    customRules: [{ id: "demo-secret", type: "secret", pattern: "\\bdemo_[a-z0-9]{20,}\\b", flags: "", confidence: 0.99 }]
  });
  const LOWER_SECRET = "demo_0123456789abcdefghij0"; // demo_ + 21 [a-z0-9]; fits ^[a-z][a-z0-9_]*$
  const cases = {
    redacted: `[REDACTED:${LOWER_SECRET}]`,
    nonVaultTokenType: `[TOKEN:${LOWER_SECRET}:deadbeef12]`,
    vaultTokenTypeSlot: `[TOKEN:tok_${LOWER_SECRET}_0123456789abcdef]` // smuggled as the vault <type> (glued to tok_)
  };
  for (const [name, text] of Object.entries(cases)) {
    const detections = await filter.detect({
      entries: collectStringEntries({ leaked: text }),
      context: { direction: "response" }
    });
    assert.ok(
      detections.some((d) => d.type === "secret"),
      `lowercase-identifier secret in a genuine-shaped marker (${name}) must still be detected on the response`
    );
  }
  // And a GENUINE marker with the same custom rule active is still skipped.
  const genuine = await filter.detect({
    entries: collectStringEntries({ ok: "[TOKEN:tok_email_a6d376389bb21964] and [REDACTED:email]" }),
    context: { direction: "response" }
  });
  assert.deepEqual(genuine, [], "genuine markers stay skipped even with a lowercase-identifier custom rule active");
});

test("response marker skip: a FAKE base64url HAECHI_ENC that is NOT a valid envelope is scanned", async () => {
  const filter = createDefaultFilterEngine();
  // base64url-shaped inner that decodes to JSON WITHOUT the envelope signature
  // (no kid/aadHash) is not a genuine marker — and a wrapped secret inside a
  // base64url-shaped-but-not-envelope frame stays scanned.
  const notEnvelope = Buffer.from(JSON.stringify({ alg: "A256GCM" }), "utf8").toString("base64url");
  const decoyDetections = await filter.detect({
    entries: collectStringEntries({ decoy: `value [HAECHI_ENC:${notEnvelope}] here` }),
    context: { direction: "response" }
  });
  // The decoy base64url itself is not a credential, so no detection from it — but
  // the point is the span is NOT excluded (verified by the wrapped-secret case
  // above); here we assert a non-envelope base64url does not get treated as a
  // genuine marker by smuggling a secret through it.
  assert.ok(!decoyDetections.some((d) => d.type === "secret"), "the decoy base64url alone is not a secret");
  const wrapped = Buffer.from(SYNTH_SECRET, "utf8").toString("base64url"); // base64url-shaped, decodes to a bare string, not an object
  const wrappedDetections = await filter.detect({
    entries: collectStringEntries({ leaked: `value [HAECHI_ENC:${wrapped}] here` }),
    context: { direction: "response" }
  });
  // The base64url ENCODING of the secret hides it from the regex (it is opt-in
  // decode-and-rescan territory), so we instead assert the marker span did not
  // suppress a clear-text secret placed next to a non-envelope marker:
  const adjacent = await filter.detect({
    entries: collectStringEntries({ leaked: `[HAECHI_ENC:${notEnvelope}]${SYNTH_SECRET}` }),
    context: { direction: "response" }
  });
  assert.ok(adjacent.some((d) => d.type === "secret"), "a secret glued to a non-genuine HAECHI_ENC marker is detected");
  assert.ok(!wrappedDetections.some((d) => d.type === "secret"), "base64url-encoded secret is not regex-detectable (documented residual)");
});

test("response marker skip: GENUINE markers are STILL skipped (no self-flagging)", async () => {
  const filter = createDefaultFilterEngine();
  // A real vault token id, a non-vault <type>:<hex> token, and a real REDACTED
  // type-name marker are recognized as genuine and excluded — no extra detection.
  const detections = await filter.detect({
    entries: collectStringEntries({
      vaultToken: "email [TOKEN:tok_email_a6d376389bb21964] ok",     // tok_<type>_<16hex>
      nonVaultToken: "card [TOKEN:card:0123456789ab] ok",            // <type>:<12hex> (core shortHash)
      redacted: "value [REDACTED:email] ok"                          // type-name
    }),
    context: { direction: "response" }
  });
  assert.deepEqual(detections, [], "genuine token/redaction markers are not re-flagged");
});

test("response marker skip: a GENUINE HAECHI_ENC envelope (real encrypt) is STILL skipped", async () => {
  const dir = await mkdtemp(join(tmpdir(), "haechi-marker-"));
  try {
    const keyFile = join(dir, "dev.keys.json");
    await initLocalKeyFile(keyFile, { force: true });
    const crypto = createLocalCryptoProvider({ keyFile });
    // Encrypt a SYNTHETIC value through the real provider, then base64url the
    // envelope exactly as core's replacementFor does — a genuine HAECHI_ENC body.
    const envelope = await crypto.encrypt({ plaintext: SYNTH_SECRET, aad: { context: {}, type: "secret" } });
    const body = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
    const filter = createDefaultFilterEngine();
    const detections = await filter.detect({
      entries: collectStringEntries({ encrypted: `value [HAECHI_ENC:${body}] here` }),
      context: { direction: "response" }
    });
    assert.deepEqual(detections, [], "a genuine encrypt-envelope marker is not re-flagged");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("response-direction skips bare number leaves (metadata) but keeps strings and request numbers", async () => {
  const filter = createDefaultFilterEngine();
  // A long Luhn-passing duration / 13-digit count is inference-server metadata,
  // not a model-leaked card/RRN — not scanned on the response.
  const respNumber = await filter.detect({
    entries: collectStringEntries({ total_duration: 4242424242424242, eval_duration: 1781129892000 }),
    context: { direction: "response" }
  });
  assert.deepEqual(respNumber, []);
  // But a card the model leaks in generated TEXT (a string) is still caught.
  const respText = await filter.detect({
    entries: collectStringEntries({ choices: [{ message: { content: "your card is 4242 4242 4242 4242" } }] }),
    context: { direction: "response" }
  });
  assert.ok(respText.some((d) => d.type === "card"));
  // The exemption is narrow — a card inside a STRINGIFIED-JSON string (kind
  // "value", not "number") is still detected on the response.
  const respStringified = await filter.detect({
    entries: collectStringEntries({ tool: JSON.stringify({ card: 4242424242424242 }) }),
    context: { direction: "response" }
  });
  assert.ok(respStringified.some((d) => d.type === "card"));
  // And the REQUEST direction still scans numbers (a client can send a card/RRN as a number).
  const reqNumber = await filter.detect({
    entries: collectStringEntries({ card: 4242424242424242, rrn: 9001011234568 }),
    context: { direction: "request" }
  });
  const reqTypes = reqNumber.map((d) => d.type);
  assert.ok(reqTypes.includes("card") && reqTypes.includes("kr_rrn"));
});

test("responseProtection.scanNumbers opts back into scanning response number leaves", async () => {
  const filter = createDefaultFilterEngine();
  // A strict deployment can set scanNumbers: true (threaded as context.scanNumbers)
  // to scan response numbers too — accepting the metadata false positives.
  const scanned = await filter.detect({
    entries: collectStringEntries({ card: 4242424242424242 }),
    context: { direction: "response", scanNumbers: true }
  });
  assert.ok(scanned.some((d) => d.type === "card"), "scanNumbers:true scans response number leaves");
});

test("the phone-rule tightening does not affect card detection", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({ card: "4242 4242 4242 4242" }),
    context: {}
  });
  const types = detections.map((d) => d.type);
  assert.ok(types.includes("card"), "a Luhn-valid 16-digit card is still detected as card");
  assert.ok(!types.includes("phone"), "a card is not misclassified as a phone");
});

test("KR phone detector ignores bare ambiguous numbers but keeps real phone formats", async () => {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({
      timestamp: 1781129892,            // unix seconds — looks phone-shaped, is not
      counter: "1719999999",            // bare 10-digit, no separator, not 0-led
      sep: "010-1234-5678",             // real, separated
      noSep: "01012345678",             // real, no separator, 0-led
      intl: "+82 10 1234 5678"          // real, +82
    }),
    context: {}
  });
  const phones = detections.filter((d) => d.type === "phone").map((d) => d.path.join(".")).sort();
  assert.deepEqual(phones, ["intl", "noSep", "sep"]);
});

// All values below are SYNTHETIC test fixtures (documented examples / fabricated
// random chars) — never real credentials, per CLAUDE.md.
async function typesFor(text, direction = "request") {
  const filter = createDefaultFilterEngine();
  const detections = await filter.detect({
    entries: collectStringEntries({ content: text }),
    context: { direction }
  });
  return new Set(detections.map((d) => d.type));
}

test("WS2b credential rules detect anchored cloud/VCS/JWT/PEM formats", async () => {
  // AWS access key id: anchored AKIA/ASIA + exactly 16 uppercase-alnum.
  assert.ok((await typesFor("AWS access key AKIAIOSFODNN7EXAMPLE used")).has("api_key"));
  // GitHub token: anchored gh[pousr]_ + long base64-ish body.
  assert.ok((await typesFor("PAT ghp_0123456789abcdefghijklmnopqrstuvwxyzAB leaked")).has("secret"));
  // Google API key: anchored AIza + 35 chars.
  assert.ok((await typesFor("key AIzaSyA1234567890abcdefghijklmnopqrstuv here")).has("api_key"));
  // Slack token: anchored xox[baprs]- + >=10-char body (low-entropy placeholder).
  assert.ok((await typesFor("xoxb-PLACEHOLDER-PLACEHOLDER-notARealSlackTokenForTests")).has("secret"));
  // JWT: three base64url segments, first starts eyJ.
  assert.ok((await typesFor("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")).has("secret"));
  // PEM private key header.
  assert.ok((await typesFor("-----BEGIN RSA PRIVATE KEY----- MIIBOg... -----END RSA PRIVATE KEY-----")).has("secret"));
});

test("WS2b credential rules are anchored — no bare-prefix / no-armor false positives", async () => {
  // AKIA without the full 16-char body must not match.
  assert.ok(!(await typesFor("the value AKIA1234 and AKIANOTLONGENOUGH appear")).has("api_key"));
  // ghp_ with a short body must not match.
  assert.ok(!(await typesFor("see ghp_short in the notes")).has("secret"));
  // AIza without a 35-char body must not match.
  assert.ok(!(await typesFor("AIzaShort is not a key")).has("api_key"));
  // Slack: too-short body and a non-allowlisted prefix char.
  assert.ok(!(await typesFor("xoxb-short and xoxe-unknownprefix")).has("secret"));
  // A dotted triplet whose first segment is not eyJ is not a JWT.
  assert.ok(!(await typesFor("build foo.bar.baz and abc.def.ghi")).has("secret"));
  // The words "private key" with no PEM armor header are not a secret.
  assert.ok(!(await typesFor("rotate the private key before the deploy")).has("secret"));
});

test("WS2b expanded assignment-secret vocabulary catches cloud/OAuth secret assignments", async () => {
  assert.ok((await typesFor("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).has("secret"));
  assert.ok((await typesFor("client_secret: 0123456789abcdef0123 committed")).has("secret"));
  assert.ok((await typesFor("refresh_token = 0123456789abcdef0123 in the env")).has("secret"));
});

// ---------------------------------------------------------------------------
// Cloud/SaaS credential expansion — anchored provider key rules. Every vector is
// a PUSH-SAFE LOW-ENTROPY synthetic value (a recognizable EXAMPLE/zero body padded
// to the exact length the rule requires) that matches our STRUCTURAL anchor but
// will not trip GitHub partner secret-scanning (no real entropy/checksum). Each
// provider: the positive detects, the near-miss is rejected, and a random base62
// run of similar length does NOT false-fire.
// ---------------------------------------------------------------------------
const padRight = (s, n) => (s + "0".repeat(n)).slice(0, n);

test("cloud-cred: OpenAI sk- (and sk-proj-) keys detect as secret; hyphen disambiguates from Stripe sk_", async () => {
  const key = `sk-${padRight("EXAMPLEEXAMPLE", 31)}`;
  const proj = `sk-proj-${padRight("EXAMPLEEXAMPLE", 31)}`;
  assert.ok((await typesFor(`OpenAI key ${key} leaked`)).has("secret"));
  assert.ok((await typesFor(`OpenAI project key ${proj} leaked`)).has("secret"));
  // Near-miss: a <20-char body must not fire.
  assert.ok(!(await typesFor("the slug sk-tooShort here")).has("secret"));
  // The underscore Stripe/OpenAI-platform sk_ form is the OTHER rule (api_key),
  // NOT this one — confirm the hyphen rule does not steal it (no overlap regression).
  const stripe = await typesFor(`Stripe sk_live_${padRight("EXAMPLEEXAMPLE", 24)} committed`);
  assert.ok(stripe.has("api_key"), "underscore sk_live_ stays api_key (existing openai-like-key rule)");
});

test("cloud-cred: Anthropic sk-ant- key detects as secret (its own rule runs first)", async () => {
  const key = `sk-ant-api03-${padRight("EXAMPLEEXAMPLE", 40)}`;
  assert.ok((await typesFor(`Anthropic key ${key} in env`)).has("secret"));
  // Near-miss: a <16-char body must not fire.
  assert.ok(!(await typesFor("the string sk-ant-tiny here")).has("secret"));
});

test("cloud-cred: Google OAuth GOCSPX- client secret detects as secret (exactly 28 chars)", async () => {
  const key = `GOCSPX-${padRight("EXAMPLEEXAMPLEEXAMPLE", 28)}`;
  assert.ok((await typesFor(`client secret ${key} in config`)).has("secret"));
  // Near-miss: not exactly 28 trailing URL-safe chars.
  assert.ok(!(await typesFor("token GOCSPX-tooShortBody here")).has("secret"));
});

test("cloud-cred: SendGrid SG.<22>.<43> API key detects as api_key", async () => {
  const key = `SG.${padRight("EXAMPLEEXAMPLE", 22)}.${padRight("EXAMPLEEXAMPLEEXAMPLE", 43)}`;
  assert.ok((await typesFor(`SendGrid key ${key} leaked`)).has("api_key"));
  // Near-miss: a short second segment must not fire.
  assert.ok(!(await typesFor("value SG.EXAMPLEEXAMPLE00000000.SHORT here")).has("api_key"));
});

test("cloud-cred: Twilio AC/SK + 32 HEX SID detects as api_key; non-hex body rejected", async () => {
  assert.ok((await typesFor(`Twilio SID AC${padRight("", 32)} in creds`)).has("api_key"));
  assert.ok((await typesFor(`Twilio API key SID SK${padRight("", 32)} in creds`)).has("api_key"));
  // Near-miss: a same-length body with non-hex chars (z) must not fire — the
  // hex-only anchor is what blocks a random base62 run.
  assert.ok(!(await typesFor(`run AC${padRight("zzzzzzzz", 32)} here`)).has("api_key"));
  // Near-miss: too short.
  assert.ok(!(await typesFor("run AC0000000000 here")).has("api_key"));
});

test("cloud-cred: npm npm_ + 36 base62 token detects as secret", async () => {
  const key = `npm_${padRight("EXAMPLEEXAMPLEEXAMPLE", 36)}`;
  assert.ok((await typesFor(`npm token ${key} published`)).has("secret"));
  // Near-miss: a short body must not fire.
  assert.ok(!(await typesFor("marker npm_short here")).has("secret"));
});

test("cloud-cred: Azure Storage AccountKey= and Twilio auth_token are caught via the assignment vocabulary", async () => {
  // An un-anchored 88-char base64 rule would false-fire on any blob, so the
  // `AccountKey=` assignment context is the anchor.
  assert.ok((await typesFor("AccountKey=EXAMPLEEXAMPLEEXAMPLEEXAMPLE000000==")).has("secret"));
  // Twilio's bare 32-hex auth token has no self-describing prefix; the assignment
  // form catches it.
  assert.ok((await typesFor(`auth_token = ${padRight("", 32)}`)).has("secret"));
});

test("cloud-cred: a random base62 run with NO provider prefix does NOT false-fire any rule", async () => {
  // 47-char random base62, no sk-/GOCSPX-/SG./AC/npm_ anchor. Every new rule is
  // anchored on a fixed prefix + charclass + length, so bare entropy never matches.
  const rnd = "Ab3xQ9KmZ2pLw7Rt5Yn1Vc8Df4Gh6Js0Bv2Nx5Mq3Pe7Wa9";
  const types = await typesFor(`a random blob ${rnd} appears`);
  assert.ok(!types.has("secret"), "random base62 must not fire secret");
  assert.ok(!types.has("api_key"), "random base62 must not fire api_key");
});

test("cloud-cred: every new credential type is a hard-block type (secret/api_key, never weakened)", () => {
  // Both target types are already in HARD_BLOCK_TYPES — confirm, do not weaken.
  assert.ok(HARD_BLOCK_TYPES.has("secret"), "secret must stay hard-block");
  assert.ok(HARD_BLOCK_TYPES.has("api_key"), "api_key must stay hard-block");
});

test("WS2b US SSN rule + SSA-range validator", async () => {
  // The public synthetic SSN passes the validator.
  assert.ok((await typesFor("US SSN 078-05-1120 on the form")).has("us_ssn"));
  // Area 666 is never issued — rejected by the validator.
  assert.ok(!(await typesFor("SSN 666-12-1234 is invalid")).has("us_ssn"));
  // Area 900-999, group 00, serial 0000 are rejected too.
  assert.ok(!(await typesFor("SSN 900-12-1234")).has("us_ssn"));
  assert.ok(!(await typesFor("SSN 078-00-1120")).has("us_ssn"));
  assert.ok(!(await typesFor("SSN 078-05-0000")).has("us_ssn"));
  // A bare 9-digit id (no separators) is never an SSN.
  assert.ok(!(await typesFor("order number 078051120 shipped")).has("us_ssn"));
});

test("WS2b IBAN rule + mod-97 checksum validator", async () => {
  // The public ECB German IBAN example passes mod-97.
  assert.ok((await typesFor("IBAN DE89370400440532013000 from ECB")).has("iban"));
  // An IBAN-shaped string that breaks mod-97 is rejected.
  assert.ok(!(await typesFor("ref DE89370400440532013001 fails checksum")).has("iban"));
});

// International-PII expansion — each new type detects its SYNTHETIC valid vector
// and REJECTS its checksum/format near-miss. All values are synthetic (computed
// from the official check algorithm or a documented invalid prefix).
test("jp_mynumber rule + mod-11 check-digit validator", async () => {
  // 123456789018: the canonical worked example (prefix 12345678901 -> check 8).
  assert.ok((await typesFor("My Number 123456789018 on the form")).has("jp_mynumber"));
  // The wrong check digit (…010) is rejected — a bare 12-digit id is not a My Number.
  assert.ok(!(await typesFor("placeholder 123456789010 fails the check digit")).has("jp_mynumber"));
});

test("fr_nir rule + 97-control-key validator", async () => {
  // 185057800604830: last 2 digits are 97-(first13 mod 97)=30.
  assert.ok((await typesFor("NIR 185057800604830 on file")).has("fr_nir"));
  // Off-by-one control key (…31) is rejected.
  assert.ok(!(await typesFor("ref 185057800604831 breaks the control key")).has("fr_nir"));
});

test("es_dni rule + mod-23 check-letter validator (DNI and NIE)", async () => {
  // 12345678Z: check letter Z = table[12345678 mod 23].
  assert.ok((await typesFor("DNI 12345678Z issued")).has("es_dni"));
  // NIE: X maps to 0 before the mod; X1234567L is valid.
  assert.ok((await typesFor("NIE X1234567L registered")).has("es_dni"));
  // The wrong check letter (A) is rejected.
  assert.ok(!(await typesFor("doc 12345678A wrong letter")).has("es_dni"));
});

test("uk_nino rule + invalid-prefix exclusions (format-only, no checksum)", async () => {
  // AB123456C: valid prefix AB, 6 digits, A-D suffix.
  assert.ok((await typesFor("NINO AB123456C on the P60")).has("uk_nino"));
  // BG is a documented never-issued prefix — rejected.
  assert.ok(!(await typesFor("code BG123456C bad prefix")).has("uk_nino"));
  // O as the 2nd letter is excluded; an invalid suffix (E, outside A-D) is excluded.
  assert.ok(!(await typesFor("AO123456C uses O as the second letter")).has("uk_nino"));
  assert.ok(!(await typesFor("AB123456E uses an out-of-range suffix")).has("uk_nino"));
});

test("the strong-anchored national IDs are hard-block; weak/format-only ones are dial-eligible", async () => {
  // fr_nir (mod-97 over a long structured run), es_dni (mod-23 + a required check
  // letter), it_codice_fiscale (16-char mixed alpha+digit + mod-26 check char) and
  // sg_nric (letter prefix + check letter) have strong NON-numeric anchors and rare
  // shapes -> hard-block (kr_rrn-grade).
  for (const type of ["fr_nir", "es_dni", "it_codice_fiscale", "sg_nric"]) {
    assert.ok(HARD_BLOCK_TYPES.has(type), `${type} must be a hard-block type`);
  }
  // jp_mynumber (a lone mod-11 check over a common 12-digit shape, ~9% FP),
  // uk_nino (no checksum), in_aadhaar (Verhoeff over a common 12-digit shape, ~9.9%
  // FP — the jp_mynumber footgun), de_steuer_id (a bare 11-digit run with NO
  // non-numeric anchor over a common length) and nl_bsn (11-proef over 9 very-common
  // digits, ~9.1% FP) carry too much FP surface to be un-allowlistable ->
  // dial-eligible (still detect + block by default; operator can clear an FP).
  for (const type of ["jp_mynumber", "uk_nino", "in_aadhaar", "de_steuer_id", "nl_bsn"]) {
    assert.ok(!HARD_BLOCK_TYPES.has(type), `${type} must stay dial-eligible (not hard-block)`);
  }
});

// EU/Asia national-ID expansion — each new type detects its SYNTHETIC/public-vector
// valid value and REJECTS its checksum/check-char near-miss. All values are
// synthetic or documented public worked examples (per CLAUDE.md).
test("it_codice_fiscale rule + mod-26 check-character validator", async () => {
  // RSSMRA85T10A562S: the public Mario Rossi worked example (16th char S is the
  // mod-26 check character over the first 15).
  assert.ok((await typesFor("codice fiscale RSSMRA85T10A562S on file")).has("it_codice_fiscale"));
  // A wrong check character (X instead of S) is rejected.
  assert.ok(!(await typesFor("doc RSSMRA85T10A562X wrong check")).has("it_codice_fiscale"));
});

test("sg_nric rule + weighted-sum check-letter validator (NRIC and FIN)", async () => {
  // S1234567D: the canonical S-series worked example (check letter D).
  assert.ok((await typesFor("NRIC S1234567D on the pass")).has("sg_nric"));
  // A FIN (F-series) computed from the same algorithm.
  assert.ok((await typesFor("FIN F1234567N registered")).has("sg_nric"));
  // A wrong check letter (A instead of D) is rejected.
  assert.ok(!(await typesFor("card S1234567A wrong letter")).has("sg_nric"));
});

test("in_aadhaar rule + Verhoeff checksum validator", async () => {
  // 234567890124: prefix 23456789012 with Verhoeff check digit 4 (leading digit
  // is non-0/1, as Aadhaar requires).
  assert.ok((await typesFor("Aadhaar 234567890124 on the e-KYC")).has("in_aadhaar"));
  // A wrong Verhoeff check digit (…125) is rejected.
  assert.ok(!(await typesFor("ref 234567890125 fails Verhoeff")).has("in_aadhaar"));
  // A 12-digit run starting 0/1 is not an Aadhaar (the leading-digit anchor).
  assert.ok(!(await typesFor("id 123456789018 here")).has("in_aadhaar"));
});

test("de_steuer_id rule + MOD 11,10 + one-repeated-digit structural validator", async () => {
  // 02476291358: the public BZSt example (first 10 have exactly one repeated digit;
  // MOD 11,10 check digit 8).
  assert.ok((await typesFor("Steuer-ID 02476291358 on file")).has("de_steuer_id"));
  // The same structural body with the wrong check digit (…357) is rejected.
  assert.ok(!(await typesFor("number 02476291357 breaks the check")).has("de_steuer_id"));
});

test("nl_bsn rule + 11-proef weighted mod-11 validator", async () => {
  // 111222333: a known synthetic test BSN that satisfies the 11-proef.
  assert.ok((await typesFor("BSN 111222333 on the formulier")).has("nl_bsn"));
  // 123456782: another 11-proef-valid synthetic BSN.
  assert.ok((await typesFor("BSN 123456782 registered")).has("nl_bsn"));
  // A clean 9-digit run that fails the 11-proef is rejected.
  assert.ok(!(await typesFor("reference 123456789 fails 11-proef")).has("nl_bsn"));
});

test("WS2b phone rules: E.164 needs a leading +, US national needs separators, bare runs rejected", async () => {
  // E.164 with a leading +.
  assert.ok((await typesFor("call +14155552671 now")).has("phone"));
  // US national with separators (both parenthesized and dashed forms).
  assert.ok((await typesFor("call (415) 555-2671 today")).has("phone"));
  assert.ok((await typesFor("call 415-555-2671 today")).has("phone"));
  // A bare separator-less, plus-less digit run is NOT a phone (collides with ids).
  assert.ok(!(await typesFor("account id 12345678901 and ticket 4155552671")).has("phone"));
});

test("WS2c kr-phone boundary: a UUID substring is not mis-detected as a phone, real numbers still match", async () => {
  const filter = createDefaultFilterEngine();
  // The '…a716-446655440000' tail of a UUID used to mis-fire (the inner
  // 16-44665544 ran the kr-phone rule). The word-boundary anchors stop a phone
  // matching as a SUBSTRING of a longer hex/dashed run.
  const uuid = await filter.detect({
    entries: collectStringEntries({ requestId: "550e8400-e29b-41d4-a716-446655440000" }),
    context: {}
  });
  assert.ok(!uuid.some((d) => d.type === "phone"), "a UUID must not produce a phone detection");
  // A bare phone-shaped run embedded in a longer alnum run is also rejected.
  const embedded = await filter.detect({
    entries: collectStringEntries({ blob: "x01012345678x" }),
    context: {}
  });
  assert.ok(!embedded.some((d) => d.type === "phone"), "a phone glued inside a longer alnum run is not matched");
  // Recall preserved: a real separated KR mobile and a +82 form still match.
  const real = await filter.detect({
    entries: collectStringEntries({
      sep: "010-1234-5678",
      intl: "+82 10 1234 5678",
      noSep: "01012345678"
    }),
    context: {}
  });
  const phonePaths = real.filter((d) => d.type === "phone").map((d) => d.path.join(".")).sort();
  assert.deepEqual(phonePaths, ["intl", "noSep", "sep"], "real KR mobile / +82 numbers still detected");
});

// ---------------------------------------------------------------------------
// WS2d — Unicode evasion via NFKC normalization. Helpers build the evaded forms
// from ASCII so the test source stays unambiguous (no literal full-width chars).
// All values are SYNTHETIC.
// ---------------------------------------------------------------------------
const toFullWidthDigits = (s) => [...s].map((c) => (/[0-9]/.test(c) ? String.fromCharCode(0xFF10 + Number(c)) : c)).join("");
const toMathBoldDigits = (s) => [...s].map((c) => (/[0-9]/.test(c) ? String.fromCodePoint(0x1D7CE + Number(c)) : c)).join("");
const FULLWIDTH_AT = String.fromCharCode(0xFF20);

test("WS2d: full-width-digit card/phone/key and full-width-@ email are detected (same-length NFKC, Case 2)", async () => {
  const filter = createDefaultFilterEngine();
  // Full-width digits fold 1:1 in length, so detection runs on the normalized
  // copy and the offsets stay valid on the original.
  const fwCard = toFullWidthDigits("4242424242424242");
  const fwPhone = `${toFullWidthDigits("010")}-${toFullWidthDigits("1234")}-${toFullWidthDigits("5678")}`;
  const fwKey = `sk_${toFullWidthDigits("1234567890abcdef1234567890abcdef")}`;
  const fwEmail = `minji.kim${FULLWIDTH_AT}example.com`;

  assert.ok((await typesFor(`card on file ${fwCard} expires`)).has("card"), "full-width card folds and is detected");
  assert.ok((await typesFor(`mobile ${fwPhone} call`)).has("phone"), "full-width KR phone folds and is detected");
  assert.ok((await typesFor(`api key ${fwKey} rotated`)).has("api_key"), "full-width-body sk_ key folds and is detected");
  assert.ok((await typesFor(`contact ${fwEmail} now`)).has("email"), "full-width-@ email folds and is detected");
});

test("WS2d: a same-length evaded match records the ORIGINAL span (offsets valid on the original; never the normalized form)", async () => {
  const filter = createDefaultFilterEngine();
  const fwCard = toFullWidthDigits("4242424242424242");
  const text = `card on file ${fwCard} expires`;
  const detections = await filter.detect({ entries: collectStringEntries({ content: text }), context: { direction: "request" } });
  const card = detections.find((d) => d.type === "card");
  assert.ok(card, "card detected");
  // The recorded value is the ORIGINAL full-width span (so tokenize/AAD/audit see
  // the real bytes), and slicing the ORIGINAL string by {start,end} reproduces it.
  assert.equal(card.value, fwCard, "recorded value is the original full-width span, not the ASCII fold");
  assert.equal(text.slice(card.start, card.end), card.value, "offsets index the ORIGINAL string correctly");
});

test("WS2d: a length-divergent evaded value (mathematical-bold KR RRN) fails closed to a whole-leaf detection (Case 3)", async () => {
  const filter = createDefaultFilterEngine();
  // Mathematical bold digits are surrogate pairs: NFKC shortens the UTF-16
  // length, so offsets cannot map back — detection must fail closed to a single
  // detection spanning the WHOLE leaf.
  const mathRrn = `${toMathBoldDigits("900101")}-${toMathBoldDigits("1234568")}`;
  const text = `resident reg number ${mathRrn} on the form`;
  const detections = await filter.detect({ entries: collectStringEntries({ content: text }), context: { direction: "request" } });
  const rrn = detections.find((d) => d.type === "kr_rrn");
  assert.ok(rrn, "length-divergent RRN is detected (folded checksum passes)");
  assert.equal(rrn.start, 0, "whole-leaf detection starts at 0");
  assert.equal(rrn.end, text.length, "whole-leaf detection covers the entire leaf");
  assert.equal(rrn.value, text, "whole-leaf detection records the whole original leaf");
});

test("WS2d: a length-divergent string with NO PII (ligatures) does NOT over-fire", async () => {
  // The fail-closed whole-leaf path runs the rules over the normalized text and
  // finds nothing — an ordinary ligature-bearing sentence (NFKC expands it) must
  // not be flagged. ﬃ/ﬁ/ﬀ are the ffi/fi/ff ligatures.
  const ligatures = `the o${"ﬃ"}ce sent a ${"ﬁ"}nal lunch memo`;
  assert.notEqual(ligatures, ligatures.normalize("NFKC"), "fixture must actually fold (length-divergent)");
  const types = await typesFor(ligatures);
  for (const t of ["email", "phone", "kr_rrn", "card", "api_key", "secret"]) {
    assert.ok(!types.has(t), `ligature prose must not fire ${t}`);
  }
});

test("WS2d: an NFKC-stable ASCII payload is byte-identical in behavior (Case 1, no regression)", async () => {
  const filter = createDefaultFilterEngine();
  const text = "email plain.user@example.org and card 4111 1111 1111 1111";
  assert.equal(text, text.normalize("NFKC"), "fixture must be NFKC-stable");
  const detections = await filter.detect({ entries: collectStringEntries({ content: text }), context: { direction: "request" } });
  // Same detections as the pre-WS2d path: exact spans, exact recorded values.
  const email = detections.find((d) => d.type === "email");
  const card = detections.find((d) => d.type === "card");
  assert.equal(email.value, "plain.user@example.org");
  assert.equal(text.slice(email.start, email.end), email.value);
  assert.equal(card.value, "4111 1111 1111 1111");
  assert.equal(text.slice(card.start, card.end), card.value);
});

test("WS2d: the response-direction marker skip survives normalization (markers are NFKC-stable)", async () => {
  const filter = createDefaultFilterEngine();
  // A tokenized round-trip echoed by the model is still skipped on the response —
  // markers are ASCII / NFKC-stable, so the Case-1 path runs exactly as before.
  const detections = await filter.detect({
    entries: collectStringEntries({ tokenized: "please email [TOKEN:tok_email_a6d376389bb21964] today" }),
    context: { direction: "response" }
  });
  assert.deepEqual(detections, []);
});

test("WS2d: a compensating contraction+expansion (equal total length, shifted offsets) never redacts the wrong bytes", async () => {
  const filter = createDefaultFilterEngine();
  // The crux bug a bare `normalized.length === value.length` check misses: a
  // length-CONTRACTING codepoint before the PII (U+10781 → "ː", 2 UTF-16 units →
  // 1) compensated by a length-EXPANDING one after it (U+0132 "Ĳ" → "IJ", 1 → 2)
  // keeps the TOTAL length equal while shifting every interior offset. The old
  // gate routed it to the exact-span path and sliced the wrong bytes (dropping a
  // trailing digit, leaking it). The sound per-codepoint check routes it to the
  // fail-closed whole-leaf path instead.
  const contractor = String.fromCodePoint(0x10781); // folds 2 units -> 1
  const expander = "Ĳ";                          // folds 1 unit -> 2
  const text = `${contractor} 010-1234-5678 ${expander}`;
  assert.equal(text.length, text.normalize("NFKC").length, "fixture must keep equal total length (the trap)");
  assert.notEqual(text, text.normalize("NFKC"), "fixture must actually fold");
  const detections = await filter.detect({ entries: collectStringEntries({ content: text }), context: { direction: "request" } });
  // Offset-integrity invariant for EVERY detection: slicing the ORIGINAL by
  // {start,end} reproduces the recorded value — i.e. the transform redacts the
  // right bytes, never an off-by-N slice.
  for (const d of detections) {
    assert.equal(text.slice(d.start, d.end), d.value, `detection ${d.type} offsets must index the original correctly`);
  }
  const phone = detections.find((d) => d.type === "phone");
  assert.ok(phone, "the phone is still detected (fail-closed whole-leaf)");
  assert.equal(phone.start, 0, "shifted fold fails closed to a whole-leaf detection");
  assert.equal(phone.end, text.length, "whole-leaf detection covers the entire leaf");
});

test("custom filter rejects unsafe regex shapes", () => {
  assert.throws(
    () => createDefaultFilterEngine({
      customRules: [
        {
          id: "unsafe",
          type: "unsafe",
          pattern: "(a+)+"
        }
      ]
    }),
    /nested quantifiers/
  );
});
