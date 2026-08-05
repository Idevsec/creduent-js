export enum ReversibilityClass {
  READ_ONLY = "read_only",
  REVERSIBLE = "reversible",
  EXTERNALLY_REVERSIBLE = "externally_reversible",
  IRREVERSIBLE = "irreversible",
}

export const REVERSIBILITY_PRECEDENCE: ReversibilityClass[] = [
  ReversibilityClass.READ_ONLY,
  ReversibilityClass.REVERSIBLE,
  ReversibilityClass.EXTERNALLY_REVERSIBLE,
  ReversibilityClass.IRREVERSIBLE,
];

export interface ToolMetadata {
  name?: string;
  reversibility_class?: string;
  declared_effect?: string;
  [key: string]: any;
}

export class ProvenanceGuard {
  private trustedRegistries: Set<string>;

  constructor(trustedRegistries?: Set<string>) {
    this.trustedRegistries = trustedRegistries || new Set(["https://creduent.idevsec.com"]);
  }

  public normalize(
    toolMetadata?: ToolMetadata | null,
    provenanceSource?: string,
    isRegistryBound: boolean = false
  ): string {
    if (!toolMetadata || typeof toolMetadata !== "object") {
      return ReversibilityClass.IRREVERSIBLE;
    }

    const rawClass = toolMetadata.reversibility_class || toolMetadata.declared_effect;

    if (!rawClass || typeof rawClass !== "string") {
      return ReversibilityClass.IRREVERSIBLE;
    }

    const rawClean = rawClass.trim().toLowerCase();
    const normalized = this.canonicalizeVocabulary(rawClean);

    if (!normalized) {
      return ReversibilityClass.IRREVERSIBLE;
    }

    // Provenance Check: Self-Assertion Guard
    // If the class was self-asserted by the tool object at runtime rather than bound by a trusted registry/policy,
    // treat as untrusted and resolve to IRREVERSIBLE.
    if (!isRegistryBound && (!provenanceSource || !this.trustedRegistries.has(provenanceSource))) {
      return ReversibilityClass.IRREVERSIBLE;
    }

    return normalized;
  }

  private canonicalizeVocabulary(rawClass: string): string | null {
    const mapping: Record<string, string> = {
      read_only: ReversibilityClass.READ_ONLY,
      readonly: ReversibilityClass.READ_ONLY,
      reversible: ReversibilityClass.REVERSIBLE,
      recoverable_local: ReversibilityClass.REVERSIBLE,
      externally_reversible: ReversibilityClass.EXTERNALLY_REVERSIBLE,
      irreversible: ReversibilityClass.IRREVERSIBLE,
      non_recoverable: ReversibilityClass.IRREVERSIBLE,
    };
    return mapping[rawClass] || null;
  }
}

export const defaultProvenanceGuard = new ProvenanceGuard();

export function normalizeReversibilityClass(
  toolMetadata?: ToolMetadata | null,
  provenanceSource?: string,
  isRegistryBound: boolean = false
): string {
  return defaultProvenanceGuard.normalize(toolMetadata, provenanceSource, isRegistryBound);
}
