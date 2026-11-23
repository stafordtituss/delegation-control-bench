/**
 * Two policy enforcement point (PEP) configurations. Each turns a scenario's
 * facts into the context a policy decision point (Cedar) evaluates. Cedar's
 * policy is the same for both; only what the PEP computes differs.
 *
 * - `final-token`: the common pattern. The PEP validates the token the acting
 *   agent presents (its own mandate) and its credential presentation, and
 *   counts actions per agent. It does not walk the delegation chain.
 * - `full-chain`: the PEP verifies the whole chain from the principal,
 *   intersects scopes across every link, enforces depth limits, checks
 *   revocation and its freshness on every link, and counts actions per
 *   principal across all of its agents.
 *
 * Both are written for this benchmark. Results describe these configurations,
 * not defects in Cedar.
 */
import { patternCovers, resourceMatches } from '@/lib/validation/policy';
import type { Mandate, ScenarioPolicy } from '@/lib/validation/schema';

export type PepConfig = 'final-token' | 'full-chain';
export const PEP_CONFIGS: readonly PepConfig[] = ['final-token', 'full-chain'];

/** Cedar context values (strings, longs, booleans, sets). */
export type CedarContext = Record<string, string | number | boolean | string[]>;

const sec = (iso: string): number => Math.floor(Date.parse(iso) / 1000);
const intersect = (sets: string[][]): string[] =>
  sets.length === 0 ? [] : sets.reduce((acc, s) => acc.filter((x) => s.includes(x))).sort();

/** Fields both configurations fill identically. */
function common(policy: ScenarioPolicy): CedarContext {
  const r = policy.request;
  const p = policy.presentation;
  return {
    now: sec(r.commitAt),
    operation: r.operation,
    purpose: r.purpose,
    audience: r.audience,
    credentialPresented: p !== undefined,
    credentialAudience: p?.audience ?? '',
    credentialNonce: p?.nonce ?? '',
    challenge: p?.expectedNonce ?? '',
    credentialNonceSeen: p ? p.seenNonces.includes(p.nonce) : false,
    credentialExpiresAt: p ? sec(p.expiresAt) : 0,
  };
}

function revokedAtCommit(policy: ScenarioPolicy, ids: string[]): boolean {
  const commit = Date.parse(policy.request.commitAt);
  return (policy.revocation?.revoked ?? []).some((e) => ids.includes(e.mandateId) && Date.parse(e.revokedAt) <= commit);
}

function linkWidens(parent: Mandate, child: Mandate): boolean {
  return (
    child.scope.operations.some((o) => !parent.scope.operations.includes(o)) ||
    child.scope.resources.some((c) => !parent.scope.resources.some((p) => patternCovers(p, c))) ||
    child.scope.purposes.some((x) => !parent.scope.purposes.includes(x)) ||
    child.audience.some((a) => !parent.audience.includes(a))
  );
}

function finalToken(policy: ScenarioPolicy): CedarContext {
  const r = policy.request;
  // The acting agent's own mandate: the last link of the chain.
  const held: Mandate | undefined = policy.mandates[policy.mandates.length - 1];
  const priorForAgent = policy.quota?.priorActions.filter((a) => a.agentId === r.actor).reduce((n, a) => n + a.count, 0) ?? 0;
  return {
    ...common(policy),
    hasMandate: held !== undefined && held.subject === r.actor,
    effectiveOperations: held?.scope.operations ?? [],
    effectivePurposes: held?.scope.purposes ?? [],
    effectiveAudience: held?.audience ?? [],
    resourceInScope: held ? held.scope.resources.some((p) => resourceMatches(p, r.resource)) : false,
    validFrom: held ? sec(held.notBefore) : 0,
    validUntil: held ? sec(held.expiresAt) : 0,
    chainVerified: held ? r.presentedProofs.includes(held.id) : false,
    revoked: held ? revokedAtCommit(policy, [held.id]) : false,
    revocationStale: false,
    delegationDepth: 0,
    maxDepth: 0,
    actionsInWindow: priorForAgent,
    actionLimit: policy.quota?.limit ?? 1_000_000,
  };
}

function fullChain(policy: ScenarioPolicy): CedarContext {
  const r = policy.request;
  const chain = policy.mandates;
  const ids = chain.map((m) => m.id);
  const origin = chain[0];
  const last = chain.at(-1);
  const continuity =
    chain.length > 0 &&
    origin.issuer.kind === 'principal' &&
    origin.issuer.id === r.principalId &&
    last!.subject === r.actor &&
    chain.every((m, i) => i === 0 || (m.parentId === chain[i - 1].id && m.issuer.id === chain[i - 1].subject && !linkWidens(chain[i - 1], m)));
  const depthLimit = chain.reduce(
    (min, m, i) => (m.maxDelegationDepth === undefined ? min : Math.min(min, i + m.maxDelegationDepth)),
    Number.MAX_SAFE_INTEGER,
  );
  const rev = policy.revocation;
  return {
    ...common(policy),
    hasMandate: chain.length > 0,
    effectiveOperations: intersect(chain.map((m) => m.scope.operations)),
    effectivePurposes: intersect(chain.map((m) => m.scope.purposes)),
    effectiveAudience: intersect(chain.map((m) => m.audience)),
    resourceInScope: chain.length > 0 && chain.every((m) => m.scope.resources.some((p) => resourceMatches(p, r.resource))),
    validFrom: chain.length ? Math.max(...chain.map((m) => sec(m.notBefore))) : 0,
    validUntil: chain.length ? Math.min(...chain.map((m) => sec(m.expiresAt))) : 0,
    chainVerified: continuity && ids.every((id) => r.presentedProofs.includes(id)),
    revoked: revokedAtCommit(policy, ids),
    revocationStale: rev ? Date.parse(r.commitAt) - Date.parse(rev.asOf) > rev.maxAgeSeconds * 1000 : false,
    delegationDepth: Math.max(chain.length - 1, 0),
    maxDepth: Math.min(depthLimit, 1_000_000),
    actionsInWindow: policy.quota?.priorActions.reduce((n, a) => n + a.count, 0) ?? 0,
    actionLimit: policy.quota?.limit ?? 1_000_000,
  };
}

export function buildContext(config: PepConfig, policy: ScenarioPolicy): CedarContext {
  return config === 'final-token' ? finalToken(policy) : fullChain(policy);
}

/**
 * Which part of each delegation control lives where in the full-chain
 * configuration. `cedar`: expressed in the Cedar policy over plain context
 * values. `pep`: computed by the PEP because the policy language cannot express
 * it over a chain of variable length.
 */
export const CONTROL_PLACEMENT: { control: string; cedar: string; pep: string }[] = [
  { control: 'Operation / purpose / audience in scope', cedar: 'set membership', pep: 'intersection across every link' },
  { control: 'Resource in scope', cedar: 'boolean check', pep: 'pattern match against every link (Cedar `like` needs literal patterns)' },
  { control: 'Validity window', cedar: 'time comparison', pep: 'tightest window across links' },
  { control: 'Revocation', cedar: 'boolean check', pep: 'status lookup for every link at commit time' },
  { control: 'Revocation freshness', cedar: 'boolean check', pep: 'age of status at commit' },
  { control: 'Delegation depth', cedar: 'integer comparison', pep: 'tightest limit across links' },
  { control: 'Chain continuity, no widening, proof per link', cedar: 'boolean check', pep: 'all of it' },
  { control: 'Principal-level quota', cedar: 'integer comparison', pep: 'sum across the principal’s agents' },
  { control: 'Credential nonce, replay, audience, expiry', cedar: 'equality and time comparison', pep: 'replay-cache lookup' },
];
