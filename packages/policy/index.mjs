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

// Compiles the base policy plus every named profile into ready policy engines
// and a resolver that maps an identity to one. A profile inherits the base
// policy's presets/actions and overrides on top (so a profile need only state
// what differs). `transform` (e.g. applyPrivacyProfile) is applied to each
// compiled policy source before buildPolicy.
export function createPolicyProfiles(policyConfig = {}, { transform } = {}) {
  const { profiles = {}, profileBinding = null, ...baseSource } = policyConfig;
  const apply = (source) => (transform ? transform(source) : source);

  const baseEngine = createPolicyEngine(buildPolicy(apply(baseSource)));
  const profileNames = Object.keys(profiles);
  const engines = new Map();

  for (const name of profileNames) {
    const override = profiles[name] ?? {};
    const merged = {
      ...baseSource,
      ...override,
      // Profile presets replace the base presets when given; actions merge over
      // the base via buildPolicy's strengthen-only rules.
      actions: { ...(baseSource.actions ?? {}), ...(override.actions ?? {}) },
      modelAllowlist: override.modelAllowlist ?? baseSource.modelAllowlist,
      rate: override.rate ?? baseSource.rate
    };
    engines.set(name, {
      policyEngine: createPolicyEngine(buildPolicy(apply(merged))),
      modelAllowlist: merged.modelAllowlist ?? null,
      rate: merged.rate ?? null
    });
  }

  if (profileBinding) {
    if (!profileBinding.default || !engines.has(profileBinding.default)) {
      throw new Error("policy.profileBinding.default must name a declared profile");
    }
    for (const map of [profileBinding.byScope ?? {}, profileBinding.byLabel ?? {}]) {
      for (const [key, target] of Object.entries(map)) {
        if (!engines.has(target)) {
          throw new Error(`policy.profileBinding maps ${key} to unknown profile: ${target}`);
        }
      }
    }
  } else if (profileNames.length > 0) {
    throw new Error("policy.profiles requires policy.profileBinding with a default");
  }

  const base = {
    policyEngine: baseEngine,
    modelAllowlist: baseSource.modelAllowlist ?? null,
    rate: baseSource.rate ?? null
  };

  return {
    base,
    hasProfiles: profileNames.length > 0,
    // Resolve identity → { profile, policyEngine, modelAllowlist, rate }.
    // Order: scope match → label match → default. Without profiles or identity,
    // the base policy applies.
    resolve(identity) {
      if (!profileBinding) {
        return { profile: null, ...base };
      }
      if (identity) {
        for (const scope of identity.scopes ?? []) {
          const name = profileBinding.byScope?.[scope];
          if (name) {
            return { profile: name, ...engines.get(name) };
          }
        }
        for (const [key, value] of Object.entries(identity.labels ?? {})) {
          const name = profileBinding.byLabel?.[`${key}=${value}`];
          if (name) {
            return { profile: name, ...engines.get(name) };
          }
        }
      }
      const fallback = profileBinding.default;
      return { profile: fallback, ...engines.get(fallback) };
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
