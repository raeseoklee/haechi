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
    id: "kr-phone",
    type: "phone",
    pattern: "(?:\\+82[-\\s]?)?0?1[016789][-.\\s]?\\d{3,4}[-.\\s]?\\d{4}",
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
    // only the secret value, not the assignment prefix.
    pattern: "(?<=\\b(?:api[_-]?key|secret|token|password)\\s*[:=]\\s*['\\\"]?)[A-Za-z0-9._~+/-]{12,}",
    flags: "gi",
    confidence: 0.85
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

export function createDefaultFilterEngine({ customRules = [] } = {}) {
  const rules = DEFAULT_RULES.concat(customRules.map(normalizeCustomRule));

  return {
    id: "haechi.filter.default",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: true,
      networkEgress: false
    },
    async detect({ entries, context }) {
      return entries.flatMap((entry) => detectEntry(entry, rules, context));
    }
  };
}

export function detectEntry(entry, rules, context = {}) {
  const detections = [];
  // On the RESPONSE direction only, skip Haechi's own transform markers so they
  // aren't re-detected: a tokenized round-trip echoes `[TOKEN:tok_…]` back, which
  // reads like a `token:<secret>` assignment — without this, Haechi blocks its
  // own token. This is response-only on purpose: a REQUEST that contains a
  // marker-shaped string is NOT Haechi output (Haechi hasn't transformed it yet),
  // so it is scanned normally — otherwise an attacker could wrap a real secret in
  // a fake `[TOKEN:…]` to evade request-side detection.
  const markerSpans = context?.direction === "response" ? haechiMarkerSpans(entry.value) : [];

  for (const rule of rules) {
    // Direction-scoped rules (e.g. injection heuristics) only run on the
    // matching traffic direction; rules without a direction run everywhere.
    if (rule.direction && rule.direction !== context?.direction) {
      continue;
    }
    const regex = new RegExp(rule.pattern, rule.flags.includes("g") ? rule.flags : `${rule.flags}g`);
    for (const match of entry.value.matchAll(regex)) {
      const value = match[0];
      if (rule.validate && !rule.validate(value)) {
        continue;
      }
      const start = match.index;
      const end = match.index + value.length;
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
        value
      });
    }
  }

  return removeOverlaps(detections);
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
