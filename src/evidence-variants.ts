/**
 * Evidence variants for each scenario.
 *
 * - `reference`: what a correctly behaving system leaves (the scenario's own bundle).
 * - `pdp-log-only`: what a deployment that keeps only policy-decision logs can
 *   show: the decision, the links it checked, and no observation of the effect.
 * - `recorded-bypass`: the system recorded a deny, but the requested action
 *   happened anyway.
 * - `unrecorded-bypass`: the requested action happened and nothing recorded a
 *   decision.
 *
 * The two bypass variants apply only to scenarios whose correct decision is deny.
 */
import type { EvidenceBundle, SecurityScenario } from '@/lib/validation/schema';

export type EvidenceVariant = 'reference' | 'pdp-log-only' | 'recorded-bypass' | 'unrecorded-bypass';
export const EVIDENCE_VARIANTS: readonly EvidenceVariant[] = ['reference', 'pdp-log-only', 'recorded-bypass', 'unrecorded-bypass'];

const plusSeconds = (iso: string, s: number): string => new Date(Date.parse(iso) + s * 1000).toISOString();

function performedRequest(s: SecurityScenario): EvidenceBundle['effect'] {
  const r = s.policy.request;
  return {
    status: 'performed',
    operation: r.operation,
    resource: r.resource,
    purpose: r.purpose,
    audience: r.audience,
    at: plusSeconds(r.commitAt, 1),
  };
}

/** Returns the bundle for a variant, or `null` when the variant does not apply. */
export function evidenceFor(s: SecurityScenario, variant: EvidenceVariant): EvidenceBundle | null {
  const ref = s.evidence;
  switch (variant) {
    case 'reference':
      return ref;
    case 'pdp-log-only':
      return { ...ref, effect: { status: 'absent' }, conflicts: [] };
    case 'recorded-bypass':
      if (s.expected.enforcement !== 'deny') return null;
      return {
        ...ref,
        decisionRecord: { decision: 'deny', recordedAt: s.policy.request.commitAt },
        effect: performedRequest(s),
      };
    case 'unrecorded-bypass':
      if (s.expected.enforcement !== 'deny') return null;
      return { signedLinks: ref.signedLinks, effect: performedRequest(s), effectSource: 'independent', conflicts: [] };
  }
}
