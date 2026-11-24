# 07. Risk scoring

## What was built
`knowledge/risk.py` computes one `RiskAssessment` per finding: five factors, a score from 0 to
100 (or none), a confidence, a P1–P4 priority and a one-sentence summary. It is pure: no I/O, no
network, no LLM.

R = 0.35 S + 0.25 E + 0.20 X + 0.10 P + 0.10 F

| Factor | Meaning | Source |
|---|---|---|
| S severity | CVSS or the tool's severity | advisory / Semgrep |
| E exposure | direct vs transitive, entry points, CI changes | graph, index |
| X exploitability | is it practically exploitable | **unknown until AI investigation** |
| P reachability | does the code import or call the package | code index |
| F fix | is a fix available | OSV |

## Decisions

### Unknown factors are excluded, not zeroed
The score is the weighted mean of the *known* factors. Missing evidence lowers the **confidence**
(high at known weight 0.75 or more, medium at 0.5 or more, else low), not the score. Alternative:
treat unknown as 0 (hides real risk) or as 0.5 (invents evidence).

### Priority thresholds and overrides
P1 at 70 or more, P2 at 50, P3 at 30, else P4. Overrides: info is always P4; critical severity
with a called package is always P1; no score gives P3. Two safeguards were added after review:

1. A P1 resting on less than half the evidence weight is demoted to P2. Without this an OSV
   finding not linked to the SBOM scored 80.6 on severity and fix alone.
2. Only critical or high severity can be P1. Because exploitability is unknown, normalising over
   the remaining 0.8 of the weight inflated scores: a medium CVE (CVSS 5.3) in a called direct
   dependency scored 73.2 and landed in P1.

### Usage from the code index, not the graph
The graph keeps one edge per node pair, so a call from a file that also imports the package
folded into the import edge and rated "called" packages as only "imported". The index has the
truth.

### Unindexed files give unknown reachability
A code finding in a Java file is not "50% reachable"; it is unknown.

### Every factor carries a rationale
So a reviewer can see why a number is what it is, for example
"express.Router called in routes/x.ts".

## Alternatives
- **CVSS only:** simple, ignores whether your code touches the package. Juice Shop shows why this
  matters (7 of 22 vulnerable packages are used).
- **EPSS / CISA KEV:** real exploit-likelihood data; a strong candidate for filling X later.
- **LLM-assigned scores:** non-deterministic and hard to audit; AI is reserved for the X factor
  and explanations (phase 5), working from these facts.

## Known limit
The weights and thresholds are a heuristic, not calibrated against real incident data.
