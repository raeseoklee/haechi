const DEFAULT_RULES = [
  {
    id: "email",
    type: "email",
    pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
    flags: "gi",
    confidence: 0.95
  },
  {
    id: "kr-phone",
    type: "phone",
    pattern: "(?:\\+82[-\\s]?)?0?1[016789][-.\\s]?\\d{3,4}[-.\\s]?\\d{4}",
    flags: "g",
    confidence: 0.9
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
    pattern: "\\b(?:api[_-]?key|secret|token|password)\\s*[:=]\\s*['\\\"]?[A-Za-z0-9._~+/-]{12,}",
    flags: "gi",
    confidence: 0.85
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
    async detect({ entries }) {
      return entries.flatMap((entry) => detectEntry(entry, rules));
    }
  };
}

export function detectEntry(entry, rules) {
  const detections = [];

  for (const rule of rules) {
    const regex = new RegExp(rule.pattern, rule.flags.includes("g") ? rule.flags : `${rule.flags}g`);
    for (const match of entry.value.matchAll(regex)) {
      const value = match[0];
      if (rule.validate && !rule.validate(value)) {
        continue;
      }
      detections.push({
        type: rule.type,
        ruleId: rule.id,
        path: entry.path,
        pathText: entry.pathText,
        start: match.index,
        end: match.index + value.length,
        confidence: rule.confidence,
        value
      });
    }
  }

  return removeOverlaps(detections);
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
