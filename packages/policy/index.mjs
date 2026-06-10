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
  },
  "local-inference": {
    defaultAction: "redact",
    actions: {
      email: "tokenize",
      phone: "mask",
      api_key: "block",
      secret: "block",
      kr_rrn: "block"
    }
  }
};

const VALID_ACTIONS = new Set(["allow", "redact", "mask", "tokenize", "encrypt", "block"]);
export const ACTION_STRENGTH = {
  allow: 0,
  redact: 1,
  mask: 1,
  tokenize: 2,
  encrypt: 2,
  block: 3
};

export function buildPolicy({
  presets = [],
  mode = "dry-run",
  defaultAction = "redact",
  actions = {},
  customRules = [],
  allowUnsafeOverrides = false
} = {}) {
  const merged = {
    mode,
    defaultAction,
    actions: {},
    customRules,
    allowUnsafeOverrides
  };

  for (const presetName of presets) {
    const preset = PRESETS[presetName];
    if (!preset) {
      throw new Error(`Unknown policy preset: ${presetName}`);
    }
    if (preset.defaultAction) {
      merged.defaultAction = preset.defaultAction;
    }
    for (const [type, action] of Object.entries(preset.actions ?? {})) {
      mergeAction(merged.actions, type, action, {
        source: `preset:${presetName}`,
        allowUnsafeOverrides
      });
    }
  }

  for (const [type, action] of Object.entries(actions)) {
    mergeAction(merged.actions, type, action, {
      source: "policy.actions",
      allowUnsafeOverrides
    });
  }
  // Injection heuristics ship report-only: unless a preset or the user sets an
  // explicit action, injection detections are audited but never transform or
  // block. This intentionally bypasses defaultAction.
  if (!merged.actions.injection) {
    merged.actions.injection = "allow";
  }
  validatePolicy(merged);
  return merged;
}

export function createPolicyEngine(policy) {
  validatePolicy(policy);

  return {
    id: "haechi.policy.reference",
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
  if (policy.allowUnsafeOverrides !== undefined && typeof policy.allowUnsafeOverrides !== "boolean") {
    throw new Error("allowUnsafeOverrides must be boolean");
  }
}

function mergeAction(target, type, action, { source, allowUnsafeOverrides }) {
  if (!VALID_ACTIONS.has(action)) {
    throw new Error(`Invalid action for ${type}: ${action}`);
  }

  const existing = target[type];
  if (!existing) {
    target[type] = action;
    return;
  }

  if (ACTION_STRENGTH[action] < ACTION_STRENGTH[existing] && !allowUnsafeOverrides) {
    throw new Error(`Policy action conflict for ${type}: ${source} cannot weaken ${existing} to ${action}`);
  }

  if (ACTION_STRENGTH[action] >= ACTION_STRENGTH[existing]) {
    target[type] = action;
  }
}
