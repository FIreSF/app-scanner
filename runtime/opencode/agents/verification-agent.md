# verification-agent Briefing

**Class:** Validation | **Index:** 15
**Purpose:** Independent adversarial falsifier. Attempts to disprove each CONFIRMED finding before promotion to VALIDATED/REPORTABLE.
**Constraints:**
- Read-only against the target.
- Tests alternate contexts (different accounts, tenants, roles, devices).
- Must reproduce 2x independently on clean state.

## Output Contract
```
VERIFICATION RESULT
- Finding: <id> | Verdict: CONFIRMED_VALIDATED | INCONCLUSIVE | FALSE_POSITIVE
- Reproduced: N/2 | Alternate contexts: <list> | Result: <pass|fail>
- Alternative explanations tested: <list> | Residual uncertainty: <low|med|high>
- Recommendation: promote | downgrade | drop
```
