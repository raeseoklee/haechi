import { isUtf8 } from "node:buffer";

// The hard-block detection types: a leak of one of these is a load-bearing
// fail-closed concern, so the WS2c precision dials (filters.minConfidence,
// filters.allowlist) may NOT suppress a detection of any of them. minConfidence
// trims only the precision-risky SOFT types; the allowlist's per-value/per-path
// exceptions are ignored for these types (the detection still fires). Exported
// so the core detect→decide path enforces the same exemption set the docs pin.
//
// Hard-block types are sensitive AND have a STRONG enough anchor that a match is
// effectively a true positive by construction, so the precision dials
// (filters.minConfidence / filters.allowlist) can never suppress them:
//   - kr_rrn / card        — checksum + constrained format
//   - fr_nir (mod-97 over a long structured 15-digit run) and es_dni (mod-23 plus
//     a required check LETTER suffix) — a random same-shaped value almost never
//     passes, and the shapes are rare in ordinary payloads.
// DELIBERATELY DIAL-ELIGIBLE (NOT hard-block):
//   - jp_mynumber — a bare 12-digit run guarded by a SINGLE mod-11 check digit
//     (~1/11 of random 12-digit numbers pass), and 12-digit ids/counters are
//     common, so a benign false positive is plausible and the operator needs the
//     allowlist escape hatch. It still detects + (per profile) blocks by default.
//   - uk_nino — NO checksum exists (format + invalid-prefix exclusions only), the
//     largest FP surface, so it too is allowlist-clearable.
export const HARD_BLOCK_TYPES = new Set(["secret", "api_key", "kr_rrn", "card", "fr_nir", "es_dni"]);

const DEFAULT_RULES = [
  {
    id: "email",
    type: "email",
    pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
    flags: "gi",
    confidence: 0.95
  },
  {
    // KR mobile numbers (01[016789] prefixes); landlines are out of scope.
    // krPhoneValid keeps a bare separator-less run from matching a timestamp/id.
    // The leading `(?<![\w+-])` / trailing `(?![\w-])` boundaries (WS2c) stop the
    // rule from matching a phone-shaped digit run that is a SUBSTRING of a longer
    // hex/alnum/dashed run — e.g. the `…a716-446655440000` tail of a UUID, where
    // the inner `16-44665544` otherwise mis-fired as a phone. The boundaries
    // never affect a real number: a KR mobile sits on a word/space/punctuation
    // edge and `+82` starts on the `+` (allowed before the boundary).
    id: "kr-phone",
    type: "phone",
    pattern: "(?<![\\w+-])(?:\\+82[-\\s]?)?0?1[016789][-.\\s]?\\d{3,4}[-.\\s]?\\d{4}(?![\\w-])",
    flags: "g",
    confidence: 0.9,
    validate: krPhoneValid
  },
  {
    id: "kr-rrn-like",
    type: "kr_rrn",
    pattern: "\\b\\d{6}[-\\s]?[1-8]\\d{6}\\b",
    flags: "g",
    confidence: 0.85,
    validate: krRrnValid
  },
  {
    id: "card-like",
    type: "card",
    pattern: "\\b(?:\\d[ -]*?){13,19}\\b",
    flags: "g",
    confidence: 0.75,
    validate: luhnValid
  },
  {
    id: "openai-like-key",
    type: "api_key",
    pattern: "\\b(?:sk|rk|pk)_[A-Za-z0-9_-]{24,}\\b",
    flags: "g",
    confidence: 0.95
  },
  {
    // AWS access key id: a long-lived (AKIA) or temporary (ASIA) key id is a
    // hard-anchored prefix + EXACTLY 16 uppercase-alphanumeric chars. The fixed
    // prefix + fixed length is what makes this high-precision (no bare base64).
    id: "aws-access-key-id",
    type: "api_key",
    pattern: "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b",
    flags: "g",
    confidence: 0.95
  },
  {
    // GitHub token: pat (ghp_), oauth (gho_), user-to-server (ghu_), server-to-
    // server (ghs_), refresh (ghr_). Anchored prefix + a long base64-ish body.
    // GitHub's own format is 36 chars after the prefix; we allow >=36 (the
    // corpus fixture is 38) and cap to keep the match bounded.
    id: "github-token",
    type: "secret",
    pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b",
    flags: "g",
    confidence: 0.95
  },
  {
    // Google API key: anchored AIza + exactly 35 chars from the URL-safe
    // alphabet. Fixed prefix + fixed length = high precision.
    id: "google-api-key",
    type: "api_key",
    pattern: "\\bAIza[0-9A-Za-z_-]{35}\\b",
    flags: "g",
    confidence: 0.9
  },
  {
    // Slack token: bot (xoxb-), user (xoxa/xoxp-), refresh (xoxr-), legacy
    // (xoxs-). Anchored xox[baprs]- + a >=10-char body. The corpus value is a
    // deliberately low-entropy placeholder, so the rule anchors on the prefix +
    // body shape, not entropy.
    id: "slack-token",
    type: "secret",
    pattern: "\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b",
    flags: "g",
    confidence: 0.9
  },
  {
    // JWT: three dot-separated base64url segments where the FIRST starts with
    // `eyJ` — the base64 of `{"`, i.e. the opening of the JSON header. Anchoring
    // on `eyJ` + two more base64url groups keeps this from matching arbitrary
    // dotted tokens (a bare base64 triplet without the JSON header is not a JWT).
    id: "jwt",
    type: "secret",
    pattern: "\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b",
    flags: "g",
    confidence: 0.9
  },
  {
    // PEM private key: the armored header. We match the header line itself
    // (`-----BEGIN [...] PRIVATE KEY-----`) — its presence is the credential
    // signal; the body is high-entropy base64 we do not need to span. Covers
    // RSA/EC/OPENSSH/DSA/ENCRYPTED variants and the bare `PRIVATE KEY` form.
    id: "pem-private-key",
    type: "secret",
    pattern: "-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    flags: "g",
    confidence: 0.98
  },
  {
    // Bearer credential. Deliberately NOT context-anchored to `Authorization:`:
    // detection runs PER STRING LEAF, and a real payload carries the credential
    // as its own leaf (`{"Authorization": "Bearer <token>"}` walks to the bare
    // value `"Bearer <token>"`), so a lookbehind requiring the header key in the
    // same string would MISS the realistic case — a recall regression on a
    // hard-block (`secret`) type. `secret` is fail-closed: a `Bearer …` prose
    // false positive is the accepted cost of never missing a leaked token.
    id: "bearer-token",
    type: "secret",
    pattern: "\\bBearer\\s+[A-Za-z0-9._~+/-]{16,}\\b",
    flags: "g",
    confidence: 0.9
  },
  {
    id: "assignment-secret",
    type: "secret",
    // Lookbehind keeps the key name out of the match so transforms replace
    // only the secret value, not the assignment prefix. The key vocabulary
    // covers the common credential-assignment names (cloud secrets, OAuth
    // client secrets, PEM/private keys, access/refresh tokens) so a
    // `<key> = <value>` leak is caught even when the value itself has no
    // self-describing prefix (e.g. an AWS secret access key is bare base64).
    pattern: "(?<=\\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|secret|aws[_-]?secret[_-]?access[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?token|refresh[_-]?token|token|password)\\s*[:=]\\s*['\\\"]?)[A-Za-z0-9._~+/-]{12,}",
    flags: "gi",
    confidence: 0.85
  },
  {
    // US SSN: AAA-GG-SSSS. The format alone collides with 9-digit ids, so a
    // validator rejects the SSA-invalid ranges (area 000/666/900-999, group 00,
    // serial 0000). The separators are required by the pattern — a bare 9-digit
    // run is intentionally NOT matched (it is indistinguishable from an id).
    id: "us-ssn",
    type: "us_ssn",
    pattern: "(?<![\\w-])\\d{3}-\\d{2}-\\d{4}(?![\\w-])",
    flags: "g",
    confidence: 0.85,
    validate: usSsnValid
  },
  {
    // IBAN: country(2 alpha) + 2 check digits + BBAN. The mod-97 checksum is
    // what makes this high-precision — a random alnum run of the right shape
    // almost never satisfies mod-97 == 1. Length 15-34 per ISO 13616.
    id: "iban",
    type: "iban",
    pattern: "(?<![A-Z0-9])[A-Z]{2}\\d{2}[A-Z0-9]{11,30}(?![A-Z0-9])",
    flags: "g",
    confidence: 0.9,
    validate: ibanValid
  },
  {
    // Japan My Number (個人番号): EXACTLY 12 digits with the official mod-11
    // weighted check digit over the first 11. A bare 12-digit run is ambiguous
    // (an id/timestamp), so jpMyNumberValid is the precision guard — only a run
    // whose 12th digit equals the prescribed check digit fires. The leading/
    // trailing boundaries (`(?<![\d-])`/`(?![\d-])`) stop the rule from matching
    // a 12-digit window inside a longer digit/dashed run. NOT hard-block: a single
    // mod-11 check digit only rejects ~10/11 of random 12-digit runs, and such
    // runs are common (ids/counters), so a benign FP is plausible and the operator
    // keeps the allowlist escape hatch (it still detects + blocks by default).
    id: "jp-mynumber",
    type: "jp_mynumber",
    pattern: "(?<![\\d-])\\d{12}(?![\\d-])",
    flags: "g",
    confidence: 0.9,
    validate: jpMyNumberValid
  },
  {
    // France NIR / INSEE social-security: 15 chars where the department field may
    // carry the Corsica `2A`/`2B` letters, validated by the control key
    // `97 - (first13 mod 97) == last2` (Corsica 2A→19, 2B→18 before the mod).
    // The control key is the precision guard — a wrong key is rejected. The
    // department alpha is optional so the pure-numeric form also matches. Anchored
    // on word boundaries; hard-block (checksummed).
    id: "fr-nir",
    type: "fr_nir",
    pattern: "(?<![\\w-])[12]\\d{2}(?:0[1-9]|1[0-2]|20)(?:\\d{2}|2[AB])\\d{6}\\d{2}(?![\\w-])",
    flags: "g",
    confidence: 0.9,
    validate: frNirValid
  },
  {
    // Spain DNI/NIE: 8 digits (DNI) or a leading X/Y/Z + 7 digits (NIE) + a check
    // letter from the mod-23 table (NIE maps X/Y/Z→0/1/2 before the mod). The
    // check letter is the precision guard — a wrong letter is rejected. The
    // letters that can never appear (I/O/U) are excluded from the suffix class so
    // an ordinary `<8-digit><letter>` token rarely even reaches the validator.
    // Hard-block (checksummed).
    id: "es-dni-nie",
    type: "es_dni",
    pattern: "(?<![\\w-])[XYZ]?\\d{7,8}[A-HJ-NP-TV-Z](?![\\w-])",
    flags: "gi",
    confidence: 0.85,
    validate: esDniValid
  },
  {
    // UK National Insurance Number: two prefix letters + 6 digits + a suffix
    // A-D. There is NO checksum, so this is FORMAT-ONLY and stays OUT of
    // HARD_BLOCK_TYPES (dial-eligible). The pattern bakes in the documented
    // invalid-prefix exclusions: 1st letter never D/F/I/Q/U/V, 2nd letter never
    // D/F/I/O/Q/U/V, and the disallowed pairs BG/GB/NK/KN/TN/NT/ZZ are rejected
    // by ukNinoValid (a negative-set the regex can't express cleanly).
    id: "uk-nino",
    type: "uk_nino",
    pattern: "(?<![\\w-])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\\d{6}[A-D](?![\\w-])",
    flags: "g",
    confidence: 0.7,
    validate: ukNinoValid
  },
  {
    // E.164 international phone: ONLY with a leading `+` (a bare digit run is an
    // id/timestamp, never matched here). `+` country digit (1-9) then 6-14 more.
    id: "e164-phone",
    type: "phone",
    pattern: "(?<![\\w+])\\+[1-9]\\d{6,14}(?![\\w])",
    flags: "g",
    confidence: 0.8
  },
  {
    // US national phone: ONLY with separators — `(NXX) NXX-XXXX` or
    // `NXX-NXX-XXXX`. A separator-less 10-digit run is deliberately NOT matched
    // (it collides with ids/timestamps; the kr-phone rule already guards bare
    // runs). Conservative by design — phone is the highest false-positive risk.
    id: "us-phone",
    type: "phone",
    pattern: "(?<![\\w-])(?:\\(\\d{3}\\)\\s?|\\d{3}-)\\d{3}-\\d{4}(?![\\w-])",
    flags: "g",
    confidence: 0.75
  },
  // Indirect prompt injection heuristics. Response/tool-result direction only,
  // and the policy default for the injection type is `allow` (report-only):
  // detections are audited regardless of action, and false-positive blocks
  // would erode trust faster than missed detections.
  {
    id: "injection-instruction-override",
    type: "injection",
    pattern: "\\b(?:ignore|disregard|forget)\\s+(?:all\\s+|any\\s+|the\\s+|your\\s+)?(?:previous|prior|earlier|above|system)\\s+(?:instructions?|rules?|prompts?|guidelines)",
    flags: "gi",
    confidence: 0.7,
    direction: "response"
  },
  {
    id: "injection-role-reassignment",
    type: "injection",
    pattern: "\\b(?:you are now|act as)\\s+(?:an?\\s+)?(?:unrestricted|jailbroken|uncensored|developer mode|dan\\b)|\\bnew (?:system )?instructions?\\s*:",
    flags: "gi",
    confidence: 0.65,
    direction: "response"
  },
  {
    id: "injection-prompt-markers",
    type: "injection",
    pattern: "<\\|im_start\\|>|<<SYS>>|\\[\\[?system\\]\\]?\\s*:",
    flags: "gi",
    confidence: 0.7,
    direction: "response"
  },
  {
    id: "injection-conceal-from-user",
    type: "injection",
    pattern: "\\bdo not (?:tell|inform|mention|reveal|show)(?:\\s+this)?(?:\\s+to)?\\s+the user\\b",
    flags: "gi",
    confidence: 0.7,
    direction: "response"
  },
  {
    id: "injection-tool-induction",
    type: "injection",
    pattern: "\\b(?:silently|secretly|immediately)\\s+(?:call|invoke|run|execute)\\s+(?:the\\s+)?[\\w.-]+\\s+tool\\b",
    flags: "gi",
    confidence: 0.6,
    direction: "response"
  }
];

export function createDefaultFilterEngine({ customRules = [], decodeAndRescan = false } = {}) {
  const rules = DEFAULT_RULES.concat(customRules.map(normalizeCustomRule));
  // The opt-in base64/percent decode-and-rescan pass (WS2d residual). Default OFF
  // => byte-identical to prior behavior. Held in the engine CLOSURE, NOT threaded
  // through the protect `context`: the request context is data and must not carry
  // this control flag (it would pollute tokenize AAD / audit).
  const decodeOptions = { decodeAndRescan: decodeAndRescan === true };

  return {
    id: "haechi.filter.default",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: false
    },
    async detect({ entries, context }) {
      return entries.flatMap((entry) => detectEntry(entry, rules, context, decodeOptions));
    }
  };
}

export function detectEntry(entry, rules, context = {}, options = {}) {
  const baseDetections = scanEntry(entry, rules, context);
  // WS2d residual — opt-in (default OFF) base64/percent decode-and-rescan. After
  // the normal NFKC scan above, if the flag is on, attempt to decode the leaf and
  // rescan the decoded text. A decoded hit has NO valid offset in the encoded leaf
  // (decoding remaps everything), so it fails closed to a WHOLE-LEAF detection of
  // the original encoded leaf — and only fires for a validator-backed/hard-block
  // hit so random base64 never false-positives. See decodeAndRescanEntry.
  if (options?.decodeAndRescan === true) {
    const decoded = decodeAndRescanEntry(entry, rules, context);
    if (decoded.length > 0) {
      return baseDetections.concat(decoded);
    }
  }
  return baseDetections;
}

// The original per-leaf NFKC scan (WS2d), unchanged. Extracted from detectEntry so
// the opt-in decode-and-rescan pass wraps it without touching the byte-identical
// default path.
function scanEntry(entry, rules, context = {}) {
  const detections = [];
  // On the RESPONSE direction, a bare JSON NUMBER leaf is inference-server
  // metadata (a nanosecond `*_duration`, a token count, a numeric id/timestamp) —
  // never a model-leaked card/phone/RRN. Scanning it only yields false positives:
  // a long Luhn-passing duration matches `card`, a 13-digit one matches `kr_rrn`.
  // The REQUEST direction still scans numbers (a client CAN send a card as a
  // number); model-leaked PII lands in generated TEXT (string leaves), which are
  // still inspected. (Accepted residual: a hostile model could exfiltrate a value
  // as a bare response number — response inspection is a secondary defense.) A
  // strict deployment can opt back in with `responseProtection.scanNumbers: true`
  // (threaded as context.scanNumbers), accepting the metadata false positives.
  if (context?.direction === "response" && entry.kind === "number" && !context?.scanNumbers) {
    return detections;
  }
  // On the RESPONSE direction only, skip Haechi's own transform markers so they
  // aren't re-detected: a tokenized round-trip echoes `[TOKEN:tok_…]` back, which
  // reads like a `token:<secret>` assignment — without this, Haechi blocks its
  // own token. This is response-only on purpose: a REQUEST that contains a
  // marker-shaped string is NOT Haechi output (Haechi hasn't transformed it yet),
  // so it is scanned normally — otherwise an attacker could wrap a real secret in
  // a fake `[TOKEN:…]` to evade request-side detection.
  // Markers are pure ASCII and NFKC-stable, so their spans are computed on the
  // ORIGINAL value exactly as before — they line up with the same-length
  // normalized scan (Case 2 below) and are irrelevant to the whole-leaf scan
  // (Case 3).
  const markerSpans = context?.direction === "response" ? haechiMarkerSpans(entry.value) : [];

  // WS2d — Unicode evasion via NFKC normalization. A client can defeat every
  // regex rule by sending PII/secrets in a Unicode form that folds to ASCII
  // (full-width digits `４２４２…`, full-width `＠`, mathematical/enclosed
  // alphanumerics). NFKC normalization maps those to their compatibility ASCII
  // form so the rules match. The crux is OFFSET INTEGRITY: detections carry
  // {start,end} into entry.value, but the transform slices the ORIGINAL string
  // (packages/core transformString). Three cases keep offsets valid:
  const value = entry.value;
  const normalized = value.normalize("NFKC");
  if (normalized === value) {
    // Case 1 (~99%): nothing folded. Detect on the original exactly as before —
    // byte-identical behavior, zero regression.
    return removeOverlaps(scanForDetections(value, rules, context, markerSpans, entry, value));
  }
  if (isPositionStableNfkc(value, normalized)) {
    // Case 2: every codepoint folded to the SAME UTF-16 length and the per-
    // codepoint folds reconstruct the whole normalization, so each original
    // character occupies the SAME offsets in `normalized` as in `value` (e.g.
    // full-width→ASCII digits/letters). A match's {start,end} on `normalized` are
    // therefore valid on the ORIGINAL value — exact-span redaction of the evaded
    // value, with the recorded `value` taken from the original slice so
    // tokenize/AAD/audit see the real bytes. A bare `normalized.length ===
    // value.length` check is UNSOUND: a length-contracting codepoint before the
    // PII compensated by a length-expanding one after it keeps the total length
    // equal yet shifts every interior offset (redacting the wrong bytes), so such
    // inputs must fall through to the Case 3 whole-leaf path. Validators still run
    // on the normalized match text (Luhn/RRN need ASCII digits).
    return removeOverlaps(scanForDetections(normalized, rules, context, markerSpans, entry, value));
  }
  // Case 3: the fold is NOT position-stable (a length-changing decomposition, or a
  // compensating contraction+expansion that shifts interior offsets). Offsets on
  // the normalized copy do NOT map back to the original, so we CANNOT do exact-span
  // redaction.
  // FAIL CLOSED: emit ONE detection per matched type covering the WHOLE leaf so
  // the transform redacts/blocks the entire leaf. Over-redacting an evasion
  // attempt is the safe failure. removeOverlaps is intentionally skipped — every
  // detection spans the whole leaf so they all "overlap"; the transform collapses
  // them to a single whole-leaf replacement via its cursor, and any `block` among
  // them blocks the payload, while preserving per-type detection reporting.
  return wholeLeafDetections(normalized, rules, context, entry, value);
}

// Run every applicable rule over `scanText` (the original value, or its
// same-length NFKC normalization). Offsets index `scanText`, which is positionally
// 1:1 with `originalValue` (Case 1: identical; Case 2: same UTF-16 length), so the
// {start,end} are valid on `originalValue`. The recorded `value` is the ORIGINAL
// slice (never the normalized form). Marker spans (response-only) are computed on
// the original and align under both cases.
function scanForDetections(scanText, rules, context, markerSpans, entry, originalValue) {
  const detections = [];
  for (const rule of rules) {
    // Direction-scoped rules (e.g. injection heuristics) only run on the
    // matching traffic direction; rules without a direction run everywhere.
    if (rule.direction && rule.direction !== context?.direction) {
      continue;
    }
    const regex = new RegExp(rule.pattern, rule.flags.includes("g") ? rule.flags : `${rule.flags}g`);
    for (const match of scanText.matchAll(regex)) {
      const matchText = match[0];
      if (rule.validate && !rule.validate(matchText)) {
        continue;
      }
      const start = match.index;
      const end = match.index + matchText.length;
      if (overlapsAny(start, end, markerSpans)) {
        continue;
      }
      detections.push({
        type: rule.type,
        ruleId: rule.id,
        path: entry.path,
        pathText: entry.pathText,
        kind: entry.kind ?? "value",
        start,
        end,
        confidence: rule.confidence,
        value: originalValue.slice(start, end)
      });
    }
  }
  return detections;
}

// Case 3 fail-closed scan: discover which types the NFKC-normalized text matches,
// then emit one whole-leaf detection per distinct type (start:0, end:value.length,
// value: the whole original leaf). The response-direction marker skip does NOT
// apply here: a length-divergent leaf cannot BE a Haechi marker (markers are ASCII
// and NFKC-stable), so an evasion attempt can never masquerade as one.
function wholeLeafDetections(normalized, rules, context, entry, originalValue, ruleFilter = null) {
  const seenTypes = new Set();
  const detections = [];
  for (const rule of rules) {
    if (rule.direction && rule.direction !== context?.direction) {
      continue;
    }
    // The decode-and-rescan caller passes a precision filter so only validator-
    // backed / hard-block rules can fire on decoded text (random base64 guard).
    // The Case-3 NFKC caller passes nothing → every rule is eligible (unchanged).
    if (ruleFilter && !ruleFilter(rule)) {
      continue;
    }
    if (seenTypes.has(rule.type)) {
      continue;
    }
    const regex = new RegExp(rule.pattern, rule.flags.includes("g") ? rule.flags : `${rule.flags}g`);
    let matched = false;
    for (const match of normalized.matchAll(regex)) {
      if (!rule.validate || rule.validate(match[0])) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      continue;
    }
    seenTypes.add(rule.type);
    detections.push({
      type: rule.type,
      ruleId: rule.id,
      path: entry.path,
      pathText: entry.pathText,
      kind: entry.kind ?? "value",
      start: 0,
      end: originalValue.length,
      confidence: rule.confidence,
      value: originalValue
    });
  }
  return detections;
}

// WS2d residual — opt-in base64/percent decode-and-rescan (default OFF). An
// always-on decode is false-positive-prone (random base64 decodes to bytes that
// can shape-match a soft rule), so this is gated behind `filters.decodeAndRescan`
// AND a precision guard: a decoded hit only fires when it is VALIDATOR-BACKED or a
// HARD-BLOCK type (a Luhn-passing card, a checksum kr_rrn/us_ssn, an IBAN mod-97,
// or a secret/api_key on its anchored rule). A decoded soft-type-without-validator
// match (a bare phone-shaped run in random decoded bytes) does NOT fire — requiring
// validators keeps precision ~100% (random base64 Luhn-passing as a 16-digit card
// is astronomically unlikely).
//
// OFFSET HANDLING (fail closed): a detection found in the DECODED text has no valid
// offset in the original encoded leaf (decoding remaps everything), so we emit a
// WHOLE-LEAF detection per matched type (start:0, end:leaf.length, value: the whole
// original encoded leaf) — exactly the WS2d Case-3 path. The transform then
// redacts/blocks the entire encoded leaf. We never map a decoded offset back.
function decodeAndRescanEntry(entry, rules, context) {
  // Only string leaves carry an encoded value; a number/boolean leaf cannot be a
  // base64/percent blob (and the response-direction number skip already applies in
  // the base scan).
  if (entry.kind === "number") {
    return [];
  }
  const decoded = decodeLeaf(entry.value);
  if (decoded === null) {
    return [];
  }
  // Reuse the Case-3 whole-leaf path, but restricted to precision-eligible rules so
  // random base64 never false-positives. `decoded` supplies the scan text; the
  // recorded detection still spans the ORIGINAL encoded leaf (entry.value).
  return wholeLeafDetections(decoded, rules, context, entry, entry.value, isDecodeEligibleRule);
}

// A decoded whole-leaf detection only fires for a "meaningful" hit: a hard-block
// type (secret/api_key/kr_rrn/card) on its anchored rule, OR a checksum-validated
// type. The `phone` type is excluded even though kr-phone carries a `validate`
// helper — that helper is a trunk-prefix heuristic, not a checksum, so a phone-
// shaped run in random decoded bytes must NOT fire (the spec's named exclusion).
function isDecodeEligibleRule(rule) {
  if (HARD_BLOCK_TYPES.has(rule.type)) {
    return true;
  }
  return typeof rule.validate === "function" && rule.type !== "phone";
}

// Attempt to decode a string leaf to UTF-8 text, returning the decoded string or
// null when the leaf does not look like (or does not cleanly round-trip as) an
// encoded value. Two encodings, each precision-guarded so a benign value is skipped
// rather than mis-decoded:
//   - base64 / base64url: the leaf must LOOK like base64 (no spaces, the base64 or
//     base64url alphabet, a valid length for that variant) within bounds, decode to
//     VALID UTF-8, and RE-ENCODE back to exactly the leaf (rejects the bytes that
//     Buffer.from leniently accepts but are not the canonical encoding of the leaf).
//   - percent-encoding: only when the leaf actually contains a `%XX` escape;
//     decodeURIComponent in a try/catch (a malformed escape → skip, never throws).
// base64 is tried first (a `%`-bearing string is not base64), then percent.
const DECODE_MIN_LEN = 16;
const DECODE_MAX_LEN = 8192;
const BASE64_STD = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64_URL = /^[A-Za-z0-9_-]+$/;

function decodeLeaf(value) {
  if (typeof value !== "string" || value.length < DECODE_MIN_LEN || value.length > DECODE_MAX_LEN) {
    return null;
  }
  const base64 = decodeBase64Leaf(value);
  if (base64 !== null) {
    return base64;
  }
  return decodePercentLeaf(value);
}

function decodeBase64Leaf(value) {
  // Standard base64: length must be a multiple of 4. base64url: length mod 4 may be
  // 0, 2, or 3 (1 is impossible for any byte run) and the alphabet is `-_` not `+/`.
  // A `%` or whitespace disqualifies it (handled by the anchored alphabet regexes).
  let encoding = null;
  if (BASE64_STD.test(value) && value.length % 4 === 0) {
    encoding = "base64";
  } else if (BASE64_URL.test(value) && value.length % 4 !== 1) {
    encoding = "base64url";
  } else {
    return null;
  }
  let bytes;
  try {
    bytes = Buffer.from(value, encoding);
  } catch {
    return null;
  }
  if (bytes.length === 0) {
    return null;
  }
  // Round-trip guard: Buffer.from is lenient (it ignores stray chars / bad padding),
  // so a non-canonical string can "decode". Re-encoding the bytes must reproduce the
  // EXACT leaf — otherwise the leaf was not really this base64 value.
  if (bytes.toString(encoding) !== value) {
    return null;
  }
  // The decoded bytes must be valid UTF-8 text; a card/RRN/secret is text. Random
  // base64 usually decodes to non-UTF-8 bytes, which we skip here (a cheap, strong
  // false-positive filter before we even run the rules).
  if (!isUtf8(bytes)) {
    return null;
  }
  return bytes.toString("utf8");
}

function decodePercentLeaf(value) {
  // Only attempt when there is an actual `%XX` escape — otherwise decodeURIComponent
  // is a no-op and we would needlessly rescan an identical string.
  if (!/%[0-9A-Fa-f]{2}/.test(value)) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    // Malformed percent-escape (e.g. a bare `%` or `%zz`) → skip, never throw.
    return null;
  }
  if (decoded === value) {
    return null;
  }
  return decoded;
}

// Sound precondition for Case 2: a match's {start,end} on the NFKC-normalized
// text map 1:1 onto the ORIGINAL value. True only when EVERY codepoint folds to
// the same number of UTF-16 units (so no interior offset shifts) AND the per-
// codepoint folds concatenate to the whole normalization (so no cross-boundary
// composition moved content). The bare `normalized.length === value.length` check
// is unsound — a contraction before the PII compensated by an expansion after it
// keeps the total length equal while shifting every interior offset, redacting the
// wrong bytes. Runs only on a leaf that actually folded (normalized !== value).
function isPositionStableNfkc(value, normalized) {
  let rebuilt = "";
  for (const ch of value) {
    const folded = ch.normalize("NFKC");
    if (folded.length !== ch.length) {
      return false;
    }
    rebuilt += folded;
  }
  return rebuilt === normalized;
}

// Spans of Haechi's own transform markers in a string, so detection can skip
// them: `[TOKEN:…]`, `[HAECHI_ENC:…]`, `[REDACTED:…]`.
function haechiMarkerSpans(text) {
  const spans = [];
  for (const m of text.matchAll(/\[(?:TOKEN|HAECHI_ENC|REDACTED):[^\]]*\]/g)) {
    spans.push([m.index, m.index + m[0].length]);
  }
  return spans;
}

function overlapsAny(start, end, spans) {
  return spans.some(([s, e]) => start < e && end > s);
}

// A bare digit run with no separators and no +82 country code is only treated as
// a KR phone number when it starts with the trunk prefix 0 (e.g. 01012345678);
// otherwise an ambiguous 10-digit value (a unix timestamp, an id, a counter)
// merely looks phone-shaped. Separated/prefixed forms (010-1234-5678,
// +82 10 1234 5678) always pass.
function krPhoneValid(match) {
  if (/[-.\s+]/.test(match)) {
    return true;
  }
  return match.startsWith("0");
}

function normalizeCustomRule(rule) {
  if (!rule.id || !rule.type || !rule.pattern) {
    throw new Error("Custom filter rule requires id, type, and pattern");
  }
  validateCustomPattern(rule.pattern);
  validateFlags(rule.flags ?? "g");
  return {
    id: rule.id,
    type: rule.type,
    pattern: rule.pattern,
    flags: rule.flags ?? "g",
    confidence: rule.confidence ?? 0.7
  };
}

function validateCustomPattern(pattern) {
  if (pattern.length > 500) {
    throw new Error("Custom filter rule pattern is too long");
  }
  if (/(?:\([^)]*[+*][^)]*\)){1}[+*{]/.test(pattern)) {
    throw new Error("Custom filter rule pattern contains nested quantifiers");
  }
  if (/\\[1-9]/.test(pattern)) {
    throw new Error("Custom filter rule pattern must not use backreferences");
  }
}

function validateFlags(flags) {
  if (!/^[dgimsuvy]*$/.test(flags)) {
    throw new Error(`Invalid custom filter flags: ${flags}`);
  }
}

function removeOverlaps(detections) {
  const sorted = detections.sort((left, right) => {
    if (left.start !== right.start) {
      return left.start - right.start;
    }
    return (right.end - right.start) - (left.end - left.start);
  });

  const accepted = [];
  let lastEnd = -1;

  for (const detection of sorted) {
    if (detection.start < lastEnd) {
      continue;
    }
    accepted.push(detection);
    lastEnd = detection.end;
  }

  return accepted;
}

function luhnValid(value) {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let alternate = false;

  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (alternate) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

function krRrnValid(value) {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 13) {
    return false;
  }

  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  const sum = weights.reduce((total, weight, index) => total + weight * Number(digits[index]), 0);
  const check = (11 - (sum % 11)) % 10;
  return check === Number(digits[12]);
}

// US SSN structural validity (SSA allocation rules). The format `AAA-GG-SSSS`
// alone collides with arbitrary 9-digit ids, so we reject the never-issued
// ranges: area 000, 666, and 900-999; group 00; serial 0000. This is what turns
// the loose shape into a high-precision detection.
function usSsnValid(value) {
  const match = /^(\d{3})-(\d{2})-(\d{4})$/.exec(value);
  if (!match) {
    return false;
  }
  const area = Number(match[1]);
  const group = Number(match[2]);
  const serial = Number(match[3]);
  if (area === 0 || area === 666 || area >= 900) {
    return false;
  }
  if (group === 0) {
    return false;
  }
  if (serial === 0) {
    return false;
  }
  return true;
}

// IBAN mod-97 checksum (ISO 7064 / ISO 13616). Move the first four chars to the
// end, map letters to 10-35, and the resulting integer must be congruent to 1
// mod 97. Computed digit-by-digit so the big integer never overflows. This
// checksum is the precision guarantee — random alnum runs almost never pass.
function ibanValid(value) {
  const iban = value.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) {
    return false;
  }
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const mapped = /\d/.test(char) ? char : String(char.charCodeAt(0) - 55);
    for (const digit of mapped) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder === 1;
}

// Japan My Number (個人番号) check digit. The official scheme: over the first 11
// digits, P = 11 - (Σ n_i · Q_i mod 11), where n_i is the i-th digit FROM THE
// RIGHT of the 11-digit prefix and Q_i = i+1 for 1≤i≤6, i-5 for 7≤i≤11. When the
// remainder is 0 or 1 the check digit is 0. The 12th digit must equal P. This
// check digit is the precision guarantee — a random 12-digit id passes only 1
// time in 10, and the corpus hard-negative (a valid-shape, wrong-check value)
// proves the rejection.
function jpMyNumberValid(value) {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 12) {
    return false;
  }
  let sum = 0;
  for (let n = 1; n <= 11; n += 1) {
    const digit = Number(digits[11 - n]);
    const weight = n <= 6 ? n + 1 : n - 5;
    sum += digit * weight;
  }
  const remainder = sum % 11;
  const check = remainder <= 1 ? 0 : 11 - remainder;
  return check === Number(digits[11]);
}

// France NIR / INSEE social-security control key. The first 13 chars are the
// body (sex, birth year/month, department, commune, order); the last 2 are the
// control key, which must equal `97 - (body mod 97)`. The Corsica department is
// written 2A/2B; the official rule substitutes 2A→19 and 2B→18 in the body
// BEFORE the mod (the rest of the body is numeric). The control key is the
// precision guarantee — a wrong key is rejected (corpus hard-negative).
function frNirValid(value) {
  const compact = value.replace(/[\s.-]/g, "").toUpperCase();
  if (!/^[12]\d{2}(?:\d{2}|0[1-9]|1[0-2]|20)(?:\d{2}|2[AB])\d{6}\d{2}$/.test(compact)) {
    return false;
  }
  const bodyRaw = compact.slice(0, 13);
  const control = Number(compact.slice(13));
  // Corsica substitution: 2A→19, 2B→18 (only the department field can be alpha).
  const body = bodyRaw.replace("2A", "19").replace("2B", "18");
  if (!/^\d{13}$/.test(body)) {
    return false;
  }
  let remainder = 0;
  for (const char of body) {
    remainder = (remainder * 10 + Number(char)) % 97;
  }
  const key = 97 - remainder;
  return key === control;
}

// Spain DNI/NIE check letter (mod-23 table). DNI is 8 digits + a letter; NIE is
// a leading X/Y/Z (mapped to 0/1/2) + 7 digits + a letter. The letter is
// `table[number mod 23]` where table = "TRWAGMYFPDXBNJZSQVHLCKE". The letter is
// the precision guarantee — a structurally valid but wrong letter is rejected
// (corpus hard-negative).
const ES_DNI_TABLE = "TRWAGMYFPDXBNJZSQVHLCKE";
const ES_NIE_PREFIX = { X: "0", Y: "1", Z: "2" };
function esDniValid(value) {
  const compact = value.replace(/[\s-]/g, "").toUpperCase();
  let body;
  let letter;
  if (/^\d{8}[A-Z]$/.test(compact)) {
    body = compact.slice(0, 8);
    letter = compact[8];
  } else if (/^[XYZ]\d{7}[A-Z]$/.test(compact)) {
    body = ES_NIE_PREFIX[compact[0]] + compact.slice(1, 8);
    letter = compact[8];
  } else {
    return false;
  }
  return ES_DNI_TABLE[Number(body) % 23] === letter;
}

// UK National Insurance Number — FORMAT-ONLY (no checksum exists), which is why
// uk_nino stays OUT of HARD_BLOCK_TYPES (dial-eligible). The regex already
// excludes the disallowed individual letters; this validator rejects the
// documented invalid PREFIX PAIRS (BG, GB, NK, KN, TN, NT, ZZ) that the regex
// cannot express as a negative set, plus the `O`-as-second-letter case (belt-and-
// braces with the regex class). The administrative `TN`/`NT` and the temporary
// `OO`/the suspended `BG` etc. are never issued, so excluding them lifts precision.
const UK_NINO_INVALID_PREFIXES = new Set(["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"]);
function ukNinoValid(value) {
  const compact = value.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{6}[A-D]$/.test(compact)) {
    return false;
  }
  const prefix = compact.slice(0, 2);
  if (UK_NINO_INVALID_PREFIXES.has(prefix)) {
    return false;
  }
  // First letter never D/F/I/Q/U/V; second letter never D/F/I/O/Q/U/V.
  if (/[DFIQUV]/.test(prefix[0]) || /[DFIOQUV]/.test(prefix[1])) {
    return false;
  }
  return true;
}
