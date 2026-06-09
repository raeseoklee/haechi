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
        secret: "block"
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
        kr_rrn: "block"
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
        secret: "block"
      }
    },
    transfer: {
      requiresAssessment: false,
      note: "Classify sector rules separately before using protected health, payment, or children's data."
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
  return {
    ...policy,
    privacyProfile: profile.id,
    actions: {
      ...(policy.actions ?? {}),
      ...profile.policy.actions
    }
  };
}
