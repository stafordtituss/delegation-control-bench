/**
 * Cedar policy decision point. One policy set, used unchanged for every PEP
 * configuration.
 */
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import type { CedarContext } from './pep';

export const CEDAR_POLICIES: Record<string, string> = {
  'in-scope': `permit (principal, action, resource)
when {
  context.hasMandate &&
  context.effectiveOperations.contains(context.operation) &&
  context.effectivePurposes.contains(context.purpose) &&
  context.effectiveAudience.contains(context.audience) &&
  context.resourceInScope &&
  context.now >= context.validFrom &&
  context.now < context.validUntil
};`,
  'chain-unverified': `forbid (principal, action, resource) when { !context.chainVerified };`,
  revoked: `forbid (principal, action, resource) when { context.revoked };`,
  'revocation-status-stale': `forbid (principal, action, resource) when { context.revocationStale };`,
  'depth-exceeded': `forbid (principal, action, resource) when { context.delegationDepth > context.maxDepth };`,
  'quota-exceeded': `forbid (principal, action, resource) when { context.actionsInWindow >= context.actionLimit };`,
  'credential-invalid': `forbid (principal, action, resource)
when {
  context.credentialPresented &&
  !(context.credentialAudience == context.audience &&
    context.credentialNonce == context.challenge &&
    !context.credentialNonceSeen &&
    context.now < context.credentialExpiresAt)
};`,
};

export interface CedarDecision {
  decision: 'allow' | 'deny';
  /** Ids of the policies that determined the decision; empty for Cedar's default deny. */
  policies: string[];
}

export const cedarVersion = (): string => cedar.getCedarVersion();

export function decideWithCedar(actor: string, resource: string, context: CedarContext): CedarDecision {
  const answer = cedar.isAuthorized({
    principal: { type: 'Agent', id: actor },
    action: { type: 'Action', id: 'invoke' },
    resource: { type: 'Resource', id: resource },
    context,
    policies: { staticPolicies: CEDAR_POLICIES },
    entities: [],
  });
  if (answer.type !== 'success') {
    throw new Error(`Cedar evaluation failed: ${JSON.stringify(answer.errors)}`);
  }
  return {
    decision: answer.response.decision,
    policies: [...answer.response.diagnostics.reason].sort(),
  };
}
