# delegation-control-bench

[![test](https://github.com/stafordtituss/delegation-control-bench/actions/workflows/test.yml/badge.svg)](https://github.com/stafordtituss/delegation-control-bench/actions/workflows/test.yml)

Where do agent delegation controls actually live, and what can evidence prove afterwards?

This benchmark runs the 16-case delegation suite from the MAESTRO threat-to-control validation module ([CloudSecurityAlliance/MAESTRO#12](https://github.com/CloudSecurityAlliance/MAESTRO/pull/12)) through:

1. **Enforcement:** two policy enforcement point (PEP) configurations in front of the same [Cedar](https://www.cedarpolicy.com/) policy set;
2. **Evidence:** two independent evidence verifiers, the module's reference verifier and the [AMEP](https://github.com/stafordtituss/amep) JavaScript verifier, over four kinds of evidence.

Everything is deterministic and offline. The full results are in [`results/RESULTS.md`](results/RESULTS.md); they are regenerated and checked on every test run.

```bash
npm install
npm test          # checks the committed results against a fresh run
npm run bench     # regenerates results/
```

## Findings

**1. Checking only the final token misses a quarter of the escalations.** The same Cedar policy passed 16/16 scenarios when the PEP verified the whole delegation chain, and 12/16 when it validated only the acting agent's own token. All four misses were allowed escalations:
- DEL-02: a delegated mandate that widened its parent;
- DEL-05: re-delegation beyond the permitted depth;
- DEL-09: a chain missing its signed ancestor;
- EPH-01: short-lived agents that together exceeded the principal's limit.

Neither configuration blocked a valid request.

**2. The delegation logic lives in the PEP, not in the policy language.** Cedar evaluated every decision, but intersecting scopes across a variable-length chain, matching data-driven resource patterns (Cedar's `like` needs literal patterns), and counting a principal's actions across agents all had to be computed by the PEP and passed in as context. The table "Where each control lives" in the results lists this per control. In practice, a policy engine alone does not make delegation safe; the code that builds its input carries most of the weight.

**3. Decision logs alone never prove that authority was preserved.** With only policy-decision records and no independent observation of the effect, the reference verifier returned `unresolved` for 16/16 scenarios. AMEP returned `preserved` for none of them, whether or not the enforcement point declared itself fail-closed (finding 5).

**4. Two evidence verifiers agreed on 42 of 56 cases, and every disagreement has one of four causes:**
- **Unit of evaluation (8 cases).** AMEP judges the *attempted invocation*, so invoking under widened or revoked authority is `violated` even when an observer confirms nothing executed. The reference verifier judges only the *effect*. Both are defensible; a specification has to say which question it answers.
- **Constraints with no place in the evidence format (3).** AMEP has no member for audience or credential binding, principal-level counts, or conflicting records. Violations of those are invisible to it. A fourth, purpose on the executed effect, was raised here as [stafordtituss/amep#14](https://github.com/stafordtituss/amep/issues/14) and fixed in AMEP 0.3.4 (spec §5.8.3). The call now declares the purpose it acts for, so DEL-04's `unrecorded-bypass` case is `violated`, as the reference verifier says. AMEP checks the purpose stated, not an unstated intention.
- **Missing mandate (2).** With no mandate at all, AMEP cannot evaluate and returns `unresolved`.
- **Precedence (1).** AMEP settles a signed deny contradicted by an executed effect as `violated` without needing the chain; the reference verifier asks for the chain first.

**5. A declared fail mode is not evidence that nothing executed.** In AMEP 0.3.0-alpha.1, if the enforcement point declared itself fail-closed, AMEP (spec §10.3) accepted a signed deny as proof that nothing executed: 12/12 denied cases became `preserved` without any effect observation, against 0/12 for the reference verifier. This benchmark raised that as [stafordtituss/amep#15](https://github.com/stafordtituss/amep/issues/15). From 0.3.0-alpha.4, the enforcement point's own declaration never settles it; only an observer's `not_executed` statement does. Re-run with 0.3.0-alpha.4, the fail-closed sensitivity is 0/12, the same as the reference verifier and as AMEP with the fail mode unknown.

## Method

- **Scenarios:** the delegation suite of the MAESTRO validation module (16 cases, 12 that should be denied and 4 valid controls). The expected decision for each comes from that module's deterministic oracle.
- **PEP configurations** ([`src/pep.ts`](src/pep.ts)):
  - `final-token` validates the acting agent's own mandate (scope, validity, revocation, proof), its credential presentation, and a per-agent action count.
  - `full-chain` verifies the whole chain from the principal: continuity, no widening at any link, proof for every link, scope intersection, the tightest validity and depth limits, revocation and its freshness on every link, and a principal-level count across agents.
- **Policy decision point** ([`src/cedar.ts`](src/cedar.ts)): one Cedar policy set, used unchanged for both configurations; decisions are scored with the MAESTRO evaluator.
- **Evidence variants** ([`src/evidence-variants.ts`](src/evidence-variants.ts)):
  - `reference`: what a correct system leaves;
  - `pdp-log-only`: decision records with no effect observation;
  - `recorded-bypass`: a recorded deny that the action went through anyway;
  - `unrecorded-bypass`: the action happened and no decision was recorded.
- **AMEP adapter** ([`src/amep-adapter.ts`](src/amep-adapter.ts)): translates each scenario and evidence bundle into an AMEP packet, signs it with fresh Ed25519 keys, and verifies it with `@stafordtituss/amep`. The file header lists what maps and what does not.

## Limitations and threats to validity

- **Same author.** The scenarios, both PEP configurations, the AMEP adapter, the reference verifier and AMEP itself were all written by the same person. The two verifiers are separate implementations with different designs, but they are not independent in the sense of different authors. Independent replication is the most useful contribution anyone could make here.
- **The configurations are illustrative.** `final-token` is a simplified version of common practice, not a model of any specific product. The results describe these configurations, not defects in Cedar.
- **Fixture-defined facts.** Classifications such as purpose are supplied by the fixtures. A real system has to obtain them, and may obtain them wrongly.
- **Only the delegation suite runs here.** The other MAESTRO scenario families (identity, data integrity, disclosure) are out of scope for this benchmark.
- **No live systems** are exercised. Detection is not measured: policy engines do not raise alerts.

## Versions

Cedar 4.15.0 (`@cedar-policy/cedar-wasm`), AMEP JavaScript verifier 0.3.4, Node.js 20 or later. Exact versions are pinned in `package.json` and recorded in `results/results.json`.

## Disclosure and license

The author of this benchmark is also the author of AMEP and of the MAESTRO validation module. AMEP is an independent project, not a CSA or IETF standard; its Internet-Draft is an individual submission and a work in progress.

The vendored scenario module is from the MAESTRO Threat Analyzer (MIT). Code in this repository is MIT licensed.
