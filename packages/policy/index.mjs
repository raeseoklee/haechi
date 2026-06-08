const PRESETS = {
  "llm-redact": {
    defaultAction: "redact",
    actions: {
      email: "redact",
      phone: "mask"
    }
  },
  "korean-pii": {
    actions: {
      kr_rrn: "block",
      phone: "mask",
      email: "redact"
    }
  },
  "secrets-only": {
    actions: {
      api_key: "block",
      secret: "block"
    }
  },
  "strict-block": {
    defaultAction: "block"
  },
  "local-only": {
    transfer: {
      allowExternal: false
    }
  },
  "mcp-basic": {
    defaultAction: "redact",
    actions: {
      api_key: "block",
      secret: "block",
      kr_rrn: "block"
    }
  }
};

const VALID_ACTIONS = new Set(["allow", "redact", "mask", "tokenize", "encrypt", "block"]);

export function buildPolicy({ presets = [], mode = "dry-run", defaultAction = "redact", actions = {}, customRules = [] } = {}) {
  const merged = {
    mode,
    defaultAction,
    actions: {},
    customRules
  };

  for (const presetName of presets) {
    const preset = PRESETS[presetName];
    if (!preset) {
      throw new Error(`Unknown policy preset: ${presetName}`);
    }
    if (preset.defaultAction) {
      merged.defaultAction = preset.defaultAction;
    }
    Object.assign(merged.actions, preset.actions ?? {});
  }

  Object.assign(merged.actions, actions);
  validatePolicy(merged);
  return merged;
}

export function createPolicyEngine(policy) {
  validatePolicy(policy);

  return {
    id: "aicel.policy.reference",
    version: "0.1.0",
    capabilities: {
      readsPlaintext: false,
      networkEgress: false
    },
    async decide({ detection, mode }) {
      const action = policy.actions[detection.type] ?? policy.defaultAction ?? "redact";
      return {
        action,
        reason: `matched:${detection.ruleId}`,
        mode: mode ?? policy.mode ?? "dry-run"
      };
    },
    async validatePolicy(candidate) {
      validatePolicy(candidate);
      return { valid: true };
    }
  };
}

export function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("Policy must be an object");
  }
  if (policy.defaultAction && !VALID_ACTIONS.has(policy.defaultAction)) {
    throw new Error(`Invalid default action: ${policy.defaultAction}`);
  }
  for (const [type, action] of Object.entries(policy.actions ?? {})) {
    if (!VALID_ACTIONS.has(action)) {
      throw new Error(`Invalid action for ${type}: ${action}`);
    }
  }
  if (policy.mode && !["dry-run", "report-only", "enforce"].includes(policy.mode)) {
    throw new Error(`Invalid policy mode: ${policy.mode}`);
  }
}
