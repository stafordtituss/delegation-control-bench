/**
 * Translates a scenario and an evidence bundle into an AMEP packet, signs it
 * with freshly generated keys, and verifies it with the published AMEP
 * JavaScript verifier (@stafordtituss/amep).
 *
 * Mapping (and what does not map):
 * - origin mandate -> AMEP `mandate`; later links -> `delegation`, signed by the issuer key.
 *   A link without a signed copy in the evidence is left out of the packet.
 * - scope operations -> claim `actions`; resources -> claim `resources` (same `prefix/*` form);
 *   a single purpose -> claim `purpose`; validity -> `nbf` / `exp`.
 * - re-delegation depth -> claim `depth`, decreasing by one per hop under a bounded parent.
 * - effect class (`ceiling`): read, list -> read; export -> external_send.
 * - the request -> `invocation`; a performed effect -> an observer-signed `effect` receipt;
 *   an effect observed not to happen -> an observer-signed `call_statement` (not_executed).
 * - decision records -> pre-execution `decision` objects. The enforcement point's fail mode is
 *   not in the scenario evidence, so it is declared `unknown` (see `denyFailMode`).
 * - revocations -> issuer-signed `revocation` objects.
 * - NOT mapped: audience, purpose of the executed effect, principal-level quotas,
 *   revocation-status freshness, credential presentations, and conflicting records.
 *   AMEP has no member for these, so a verdict that depends on them can differ.
 */
import { Key, keyset, sdk, verifyPacket, type AmepObject, type AmepResult } from '@stafordtituss/amep';
import type { EvidenceBundle, Mandate, SecurityScenario } from '@/lib/validation/schema';

const CEILING_ORDER = ['read', 'write_local', 'write_shared', 'external_send', 'destructive', 'financial'];
const OPERATION_CLASS: Record<string, string> = {
  read: 'read',
  list: 'read',
  infer: 'read',
  export: 'external_send',
  approve_access: 'write_shared',
};

export function effectClass(operation: string): string {
  const c = OPERATION_CLASS[operation];
  if (!c) throw new Error(`no AMEP effect class for operation "${operation}"`);
  return c;
}

const ceilingOf = (ops: string[]): string =>
  ops.map(effectClass).reduce((a, b) => (CEILING_ORDER.indexOf(b) > CEILING_ORDER.indexOf(a) ? b : a), 'read');

function depths(chain: Mandate[]): (number | undefined)[] {
  const out: (number | undefined)[] = [];
  chain.forEach((m, i) => {
    const parent = i > 0 ? out[i - 1] : undefined;
    const inherited = parent === undefined ? undefined : Math.max(parent - 1, 0);
    const own = m.maxDelegationDepth;
    out.push(own === undefined ? inherited : inherited === undefined ? own : Math.min(own, inherited));
  });
  return out;
}

export interface AmepOutcome {
  outcome: 'preserved' | 'violated' | 'unresolved';
  invariant: string;
  reason: string;
}

/**
 * `denyFailMode`: what the packet declares about the enforcement point behind a
 * recorded deny. The scenario evidence does not say, so the benchmark uses
 * `unknown` and reports `closed` separately as a sensitivity check. Up to AMEP
 * 0.3.0-alpha.3, spec 10.3 let a verified pre-execution deny from a fail-closed
 * enforcement point settle "nothing executed" without an observer's record; from
 * 0.3.0-alpha.4 the declaration never settles it (stafordtituss/amep#15).
 */
export function verifyWithAmep(
  s: SecurityScenario,
  evidence: EvidenceBundle,
  { denyFailMode = 'unknown' }: { denyFailMode?: 'unknown' | 'closed' } = {},
): AmepOutcome {
  const issuer = Key.generate('issuer-1', ['issuer']);
  const host = Key.generate('host-1', ['host']);
  const observer = Key.generate('observer-1', ['observer']);
  const r = s.policy.request;
  const chain = s.policy.mandates;
  const signed = new Set(evidence.signedLinks);
  const d = depths(chain);
  const objects: AmepObject[] = [];

  chain.forEach((m, i) => {
    if (!signed.has(m.id)) return;
    const claimSet = sdk.claims(m.scope.operations, m.scope.resources, ceilingOf(m.scope.operations), m.expiresAt, {
      nbf: m.notBefore,
      purpose: m.scope.purposes.length === 1 ? m.scope.purposes[0] : undefined,
      depth: d[i],
    });
    const obj =
      i === 0
        ? sdk.mandate(m.id, r.principalId, claimSet, { issuer: m.issuer.id, subjectAgent: m.subject })
        : sdk.delegation(m.id, m.parentId ?? '', claimSet, { delegate: m.subject });
    objects.push(issuer.sign(obj));
  });

  for (const e of s.policy.revocation?.revoked ?? []) {
    objects.push(issuer.sign(sdk.revocation(e.mandateId, e.revokedAt, { id: `rev-${e.mandateId}` })));
  }

  objects.push(host.sign(sdk.interpretation('a-1', 'bench-adapter', '1')));
  const authorityRef = chain.length ? chain[chain.length - 1].id : 'no-mandate';
  objects.push(
    host.sign(sdk.invocation('i-1', authorityRef, 'a-1', r.commitAt, r.operation, r.resource, effectClass(r.operation), { actor: r.actor })),
  );

  if (evidence.decisionRecord) {
    const deny = evidence.decisionRecord.decision === 'deny';
    objects.push(
      host.sign(
        sdk.decision('i-1', deny ? 'violated' : 'preserved', deny ? 'deny' : 'allow', 'pre_execution', {
          id: 'd-1',
          enforcement: deny ? sdk.enforcement('pep:gateway', denyFailMode) : undefined,
        }),
      ),
    );
  }

  const fx = evidence.effect;
  if (fx.status === 'performed') {
    const body = sdk.effectBody(fx.operation, fx.resource, effectClass(fx.operation), fx.at);
    const observedBy = evidence.effectSource === 'self_asserted' ? r.actor : 'observer:gateway';
    objects.push(observer.sign(sdk.effect('e-1', 'i-1', observedBy, 'L1', body)));
  } else if (fx.status === 'not_performed') {
    objects.push(observer.sign(sdk.callStatement('c-1', 'i-1', 'observer:gateway', 'not_executed', 0, fx.observedAt)));
  }

  const { verdict, results } = verifyPacket(sdk.packet(objects), keyset(issuer, host, observer));
  const forInvocation: AmepResult = results.find((x) => x.id === 'i-1') ?? verdict;
  // Report the packet-level verdict (worst outcome), naming the invariant behind it.
  const worst = verdict.outcome !== 'preserved' ? verdict : forInvocation;
  return { outcome: worst.outcome, invariant: worst.invariant, reason: worst.reason };
}
