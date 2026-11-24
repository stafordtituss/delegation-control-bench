import { describe, it, expect } from 'vitest';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DELEGATION_SUITE, runBenchmark, runEnforcement, runEvidence } from '../src/bench';
import { buildContext } from '../src/pep';
import { decideWithCedar } from '../src/cedar';
import { verifyWithAmep } from '../src/amep-adapter';
import { evidenceFor } from '../src/evidence-variants';
import { renderMarkdown } from '../src/report';

const byId = (id: string) => DELEGATION_SUITE.find((s) => s.id === id)!;

describe('scenario selection', () => {
  it('runs the 16-case delegation suite', () => {
    expect(DELEGATION_SUITE).toHaveLength(16);
  });
});

describe('enforcement', () => {
  const { rows, summaries } = runEnforcement();
  const summary = (c: string) => summaries.find((s) => s.config === c)!;

  it('full-chain PEP with Cedar matches the oracle on every scenario', () => {
    expect(summary('full-chain')).toMatchObject({ pass: 16, fail: 0, falseAllow: [], falseDeny: [] });
  });

  it('final-token PEP misses chain-level escalations and never over-blocks', () => {
    expect(summary('final-token').falseAllow.sort()).toEqual(['DEL-02', 'DEL-05', 'DEL-09', 'EPH-01']);
    expect(summary('final-token').falseDeny).toEqual([]);
  });

  it('records which Cedar policy denied each request', () => {
    const del05 = rows.find((r) => r.scenarioId === 'DEL-05')!;
    expect(del05.decisions['full-chain'].policies).toEqual(['depth-exceeded']);
    const del02 = rows.find((r) => r.scenarioId === 'DEL-02')!;
    expect(del02.decisions['full-chain'].policies).toContain('chain-unverified');
  });

  it('uses the same Cedar policy text for both configurations', () => {
    const s = byId('DEL-01');
    for (const c of ['final-token', 'full-chain'] as const) {
      expect(decideWithCedar(s.policy.request.actor, s.policy.request.resource, buildContext(c, s.policy)).decision).toBe('allow');
    }
  });
});

describe('evidence', () => {
  const rows = runEvidence();

  it('reference verifier: decision logs alone never establish authority', () => {
    expect(rows.filter((r) => r.variant === 'pdp-log-only').every((r) => r.maestro === 'unresolved')).toBe(true);
  });

  it('AMEP never reports preserved from decision logs alone when the fail mode is unknown', () => {
    expect(rows.filter((r) => r.variant === 'pdp-log-only').some((r) => r.amep.outcome === 'preserved')).toBe(false);
  });

  it('AMEP judges the attempt: invoking under revoked authority is violated even when nothing executed', () => {
    const r = rows.find((x) => x.scenarioId === 'DEL-07' && x.variant === 'reference')!;
    expect(r).toMatchObject({ maestro: 'preserved', amep: { outcome: 'violated', invariant: 'I6' } });
  });

  it('a declared fail-closed enforcement point does not let AMEP accept a signed deny without an effect observation', () => {
    const { sensitivity } = runBenchmark().evidence;
    expect(sensitivity).toMatchObject({ cases: 12, referencePreserved: 0, amepPreservedWhenFailModeUnknown: 0, amepPreservedWhenFailClosed: 0 });
  });

  it('both verifiers report a recorded bypass of an operation escalation as violated', () => {
    const r = rows.find((x) => x.scenarioId === 'DEL-02' && x.variant === 'recorded-bypass')!;
    expect(r).toMatchObject({ maestro: 'violated', agree: true });
  });

  it('every disagreement is explained', () => {
    for (const r of rows.filter((x) => !x.agree)) expect(r.difference, `${r.scenarioId}/${r.variant}`).not.toMatch(/unexplained/);
  });

  it('AMEP catches an unrecorded depth escalation from the evidence alone', () => {
    const s = byId('DEL-05');
    expect(verifyWithAmep(s, evidenceFor(s, 'unrecorded-bypass')!)).toMatchObject({ outcome: 'violated', invariant: 'I1' });
  });
});

describe('committed results', () => {
  const dir = path.resolve(__dirname, '../results');
  const fresh = runBenchmark();
  const json = JSON.stringify(fresh, null, 2) + '\n';
  const md = renderMarkdown(fresh);

  it('match a fresh run (set UPDATE_RESULTS=1 to regenerate)', () => {
    if (process.env.UPDATE_RESULTS === '1') {
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, 'results.json'), json);
      writeFileSync(path.join(dir, 'RESULTS.md'), md);
    }
    expect(existsSync(path.join(dir, 'results.json'))).toBe(true);
    expect(readFileSync(path.join(dir, 'results.json'), 'utf8')).toBe(json);
    expect(readFileSync(path.join(dir, 'RESULTS.md'), 'utf8')).toBe(md);
  });
});
