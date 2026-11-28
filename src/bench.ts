/**
 * The benchmark itself: pure functions that produce a deterministic result
 * object. `run.ts` writes it to disk.
 */
import { AGENT_IDENTITY_SCENARIOS } from '@/data/validation/agent-identity-scenarios';
import { evaluate, type Failure } from '@/lib/validation/evaluate';
import { verifyEvidence, type CheckCode } from '@/lib/validation/policy';
import type { AuthorityVerdict, EvidenceBundle, ScenarioRun, SecurityScenario } from '@/lib/validation/schema';
import { VERSION as AMEP_VERSION } from '@stafordtituss/amep';
import { cedarVersion, decideWithCedar } from './cedar';
import { verifyWithAmep, type AmepOutcome } from './amep-adapter';
import { EVIDENCE_VARIANTS, evidenceFor, type EvidenceVariant } from './evidence-variants';
import { PEP_CONFIGS, buildContext, type PepConfig } from './pep';

export const DELEGATION_SUITE: SecurityScenario[] = AGENT_IDENTITY_SCENARIOS.filter((s) => s.suites.includes('delegation'));

export interface EnforcementRow {
  scenarioId: string;
  title: string;
  expected: 'allow' | 'deny';
  decisions: Record<PepConfig, { decision: 'allow' | 'deny'; policies: string[]; outcome: string }>;
}

export interface EnforcementSummary {
  config: PepConfig;
  pass: number;
  fail: number;
  total: number;
  falseAllow: string[];
  falseDeny: string[];
}

export function runEnforcement(scenarios = DELEGATION_SUITE) {
  const rows: EnforcementRow[] = scenarios.map((s) => ({
    scenarioId: s.id,
    title: s.title,
    expected: s.expected.enforcement!,
    decisions: {} as EnforcementRow['decisions'],
  }));
  const summaries: EnforcementSummary[] = [];
  for (const config of PEP_CONFIGS) {
    const runs: ScenarioRun[] = scenarios.map((s, i) => {
      const d = decideWithCedar(s.policy.request.actor, s.policy.request.resource, buildContext(config, s.policy));
      rows[i].decisions[config] = { ...d, outcome: '' };
      return { scenarioId: s.id, system: `cedar/${config}`, observations: { enforcement: { decision: d.decision } } };
    });
    const report = evaluate(scenarios, runs, { system: `cedar/${config}` });
    report.results.forEach((r, i) => (rows[i].decisions[config].outcome = r.dimensions.enforcement.outcome));
    const enf = report.dimensions.enforcement;
    const kinds = (k: Failure['failureKind']) => report.failures.filter((f) => f.dimension === 'enforcement' && f.failureKind === k).map((f) => f.scenarioId);
    summaries.push({ config, pass: enf.pass, fail: enf.fail, total: enf.total, falseAllow: kinds('false_allow'), falseDeny: kinds('false_deny') });
  }
  return { rows, summaries };
}

export interface EvidenceRow {
  scenarioId: string;
  variant: EvidenceVariant;
  maestro: AuthorityVerdict;
  maestroBasis: string[];
  amep: AmepOutcome;
  agree: boolean;
  difference?: string;
}

const UNMAPPED: Partial<Record<CheckCode, string>> = {
  'delegation.purpose_outside_scope': 'the request states no purpose, so AMEP has none to check against the claims (spec 5.8.3)',
  'delegation.audience_outside_scope': 'AMEP claims have no audience member',
  'credential.audience_mismatch': 'credential presentations are outside AMEP’s scope',
  'credential.nonce_mismatch': 'credential presentations are outside AMEP’s scope',
  'credential.replayed': 'credential presentations are outside AMEP’s scope',
  'quota.principal_limit_exceeded': 'AMEP has no principal-level action count across agents',
  'revocation.status_stale': 'revocation-status age is not mapped',
  'delegation.unverifiable_link': 'proof presented at decision time is not represented in the packet',
};

function explain(maestro: ReturnType<typeof verifyEvidence>, amep: AmepOutcome, bundle: EvidenceBundle): string {
  const codes = maestro.findings.map((f) => f.code);
  if (codes.includes('evidence.conflicting_records')) return 'conflicting records are not representable in an AMEP packet';
  if (bundle.effect.status !== 'performed' && amep.outcome === 'violated' && (amep.invariant === 'I1' || amep.invariant === 'I6'))
    return 'unit of evaluation: AMEP judges the attempted invocation, so invoking under widened (I1) or revoked (I6) authority is a violation even though nothing executed; the reference verifier judges only the effect';
  if (amep.invariant === 'I7' && /no root mandate/.test(amep.reason) && maestro.verdict === 'preserved')
    return 'AMEP needs a root mandate to evaluate an invocation and reports unresolved without one, even when nothing executed';
  if (codes.includes('evidence.missing_link') && amep.invariant === 'I11')
    return 'AMEP settles a signed deny contradicted by an effect (I11) without needing the chain; the MAESTRO verifier requires every signed link first';
  if (codes.includes('evidence.missing_link') && amep.outcome === 'preserved')
    return 'AMEP accepts a fail-closed signed deny with no effect as preserved without the chain (spec 10.3); the MAESTRO verifier requires every signed link first';
  if (maestro.violatedChecks.includes('delegation.no_principal_mandate'))
    return 'with no mandate at all, AMEP reports no root mandate (unresolved); the MAESTRO verifier treats the authoritative policy as showing no authority exists';
  if (codes.includes('evidence.missing_decision_record'))
    return 'AMEP does not require a pre-execution decision record when the effect is within authority';
  const unmapped = maestro.violatedChecks.map((c) => UNMAPPED[c]).filter((x): x is string => !!x);
  if (unmapped.length) return [...new Set(unmapped)].join('; ');
  return 'unexplained: needs investigation';
}

export function runEvidence(scenarios = DELEGATION_SUITE): EvidenceRow[] {
  const rows: EvidenceRow[] = [];
  for (const s of scenarios) {
    for (const variant of EVIDENCE_VARIANTS) {
      const bundle = evidenceFor(s, variant);
      if (!bundle) continue;
      const m = verifyEvidence(s.policy, bundle);
      const a = verifyWithAmep(s, bundle);
      const agree = m.verdict === a.outcome;
      rows.push({
        scenarioId: s.id,
        variant,
        maestro: m.verdict,
        maestroBasis: [...m.findings.map((f) => f.code), ...m.violatedChecks],
        amep: a,
        agree,
        difference: agree ? undefined : explain(m, a, bundle),
      });
    }
  }
  return rows;
}

export function runBenchmark() {
  const enforcement = runEnforcement();
  const evidence = runEvidence();
  const count = (v: EvidenceVariant, verdict: AuthorityVerdict, who: 'maestro' | 'amep') =>
    evidence.filter((r) => r.variant === v && (who === 'maestro' ? r.maestro : r.amep.outcome) === verdict).length;
  const byVariant = Object.fromEntries(
    EVIDENCE_VARIANTS.map((v) => {
      const rs = evidence.filter((r) => r.variant === v);
      return [
        v,
        {
          cases: rs.length,
          agree: rs.filter((r) => r.agree).length,
          maestro: { preserved: count(v, 'preserved', 'maestro'), violated: count(v, 'violated', 'maestro'), unresolved: count(v, 'unresolved', 'maestro') },
          amep: { preserved: count(v, 'preserved', 'amep'), violated: count(v, 'violated', 'amep'), unresolved: count(v, 'unresolved', 'amep') },
        },
      ];
    }),
  );
  // Sensitivity: decision-log-only evidence for denied requests, with the enforcement point declared fail-closed.
  const denied = DELEGATION_SUITE.filter((s) => s.expected.enforcement === 'deny');
  const failClosed = denied.map((s) => ({
    scenarioId: s.id,
    unknown: verifyWithAmep(s, evidenceFor(s, 'pdp-log-only')!).outcome,
    closed: verifyWithAmep(s, evidenceFor(s, 'pdp-log-only')!, { denyFailMode: 'closed' }).outcome,
  }));
  const sensitivity = {
    question: 'Does a signed pre-execution deny, with no observation of the effect, establish that nothing executed?',
    cases: denied.length,
    amepPreservedWhenFailModeUnknown: failClosed.filter((x) => x.unknown === 'preserved').length,
    amepPreservedWhenFailClosed: failClosed.filter((x) => x.closed === 'preserved').length,
    referencePreserved: denied.filter((s) => verifyEvidence(s.policy, evidenceFor(s, 'pdp-log-only')!).verdict === 'preserved').length,
  };
  return {
    kind: 'delegation-control-bench.results',
    version: 1,
    tools: { cedar: cedarVersion(), amep: AMEP_VERSION, scenarios: 'MAESTRO validation module (vendored)' },
    scenarioCount: DELEGATION_SUITE.length,
    enforcement,
    evidence: { byVariant, rows: evidence, sensitivity },
  };
}

export type BenchmarkResults = ReturnType<typeof runBenchmark>;
