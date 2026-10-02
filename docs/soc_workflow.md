# SOC Analyst Workflow

```text
Network event → IDS detection → Alert → SOC queue → Triage
→ Investigate context → Determine severity → Escalate / Resolve / False Positive
→ Document outcome and tuning feedback
```

A Tier 1 analyst validates alert fields, time and scope; checks asset ownership and expected change windows; reviews authorized firewall, authentication, DNS/application and endpoint evidence; finds related alerts; distinguishes anomalous from malicious; changes status to `INVESTIGATING`; documents sources and observations; then resolves, marks false positive, or escalates under playbook criteria. Tier 1 does not infer attribution from one statistic.

## Interview demonstration

1. Run the generator and show its documentation IP ranges.
2. Compare one normal and one high-rate input.
3. Explain features and a matched rule.
4. Show anomaly component scores and the genuinely calculated ML probability.
5. Explain configurable hybrid weighting and threshold assumptions.
6. Open the alert, document a note, update status, and show the audit-backed timeline.
7. Discuss false positives, test coverage, and the ethical boundary.
