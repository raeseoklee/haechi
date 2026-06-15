import { ACTION_STRENGTH } from "../policy/index.mjs";

const PROFILES = {
  "kr-pipa": {
    id: "kr-pipa",
    region: "KR",
    regulations: ["PIPA", "Credit Information Act"],
    policy: {
      actions: {
        kr_rrn: "block",
        phone: "mask",
        email: "redact",
        card: "block",
        api_key: "block",
        secret: "block",
        // A Japan My Number leak is as sensitive as a national ID and is a
        // checksummed true-positive — block it in every profile so a non-JP
        // deployment that happens to process JP data is still covered.
        jp_mynumber: "block"
      }
    },
    transfer: {
      requiresAssessment: true,
      note: "Document cross-border transfer purpose, recipient, retention, and user notice before production use."
    }
  },
  "eu-gdpr": {
    id: "eu-gdpr",
    region: "EU",
    regulations: ["GDPR"],
    policy: {
      actions: {
        email: "tokenize",
        phone: "mask",
        card: "block",
        api_key: "block",
        secret: "block",
        kr_rrn: "block",
        // EU national IDs — France NIR, Spain DNI/NIE, UK National Insurance
        // Number — are GDPR special-category-adjacent identifiers; block them.
        fr_nir: "block",
        es_dni: "block",
        uk_nino: "block",
        jp_mynumber: "block"
      }
    },
    transfer: {
      requiresAssessment: true,
      note: "Treat model/tool transfer as processor/subprocessor transfer and document SCC/TIA evidence outside Haechi."
    }
  },
  "us-general": {
    id: "us-general",
    region: "US",
    regulations: ["CCPA/CPRA", "HIPAA-sensitive deployments require separate controls"],
    policy: {
      actions: {
        email: "redact",
        phone: "mask",
        card: "block",
        api_key: "block",
        secret: "block",
        jp_mynumber: "block"
      }
    },
    transfer: {
      requiresAssessment: false,
      note: "Classify sector rules separately before using protected health, payment, or children's data."
    }
  },
  "jp-appi": {
    id: "jp-appi",
    region: "JP",
    regulations: ["APPI"],
    policy: {
      actions: {
        // My Number (個人番号) is a special-care personal-information identifier
        // under the My Number Act; block it. The EU/KR IDs are also blocked so a
        // mixed-region payload is covered, matching the cross-profile convention.
        jp_mynumber: "block",
        phone: "mask",
        email: "redact",
        card: "block",
        api_key: "block",
        secret: "block",
        kr_rrn: "block"
      }
    },
    transfer: {
      requiresAssessment: true,
      note: "Document the My Number Act handling basis, purpose limitation, and cross-border transfer notice before production use."
    }
  }
};

export function listPrivacyProfiles() {
  return Object.values(PROFILES).map((profile) => structuredClone(profile));
}

export function getPrivacyProfile(id) {
  const profile = PROFILES[id];
  if (!profile) {
    throw new Error(`Unknown privacy profile: ${id}`);
  }
  return structuredClone(profile);
}

export function applyPrivacyProfile(policy = {}, profileId) {
  const profile = getPrivacyProfile(profileId);
  const actions = { ...(policy.actions ?? {}) };

  // Profiles are baseline defaults: they may strengthen an action but must
  // never silently weaken an explicitly stricter user setting.
  for (const [type, action] of Object.entries(profile.policy.actions)) {
    const existing = actions[type];
    if (!existing || ACTION_STRENGTH[action] > ACTION_STRENGTH[existing]) {
      actions[type] = action;
    }
  }

  return {
    ...policy,
    privacyProfile: profile.id,
    actions
  };
}
