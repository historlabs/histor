# Written proof — Point-of-sale age estimator

Sandbox `demo-001` · plan `sha256:7c29182e4070eda49c49c768f710fe55d509292558b1b93a28496b1a131f1354`

> Written proof of the activities carried out in the AI regulatory sandbox (AI Act Art. 57(7)), with the elements of the draft implementing act, Art. 6(2). Documentation evidence for notified bodies and market surveillance authorities (draft implementing act Art. 6(2)). It does not have the status or legal effect of an EU declaration of conformity under AI Act Art. 47, and exiting a sandbox grants no presumption of conformity.

## 1. Applicant and AI system

- **Provider**: Demo Provider
- **System**: Point-of-sale age estimator
- **Intended purpose**: Estimate whether a customer is 18 or over at unattended points of sale for age-restricted products, so that the machine either completes or refuses the sale. The harm the plan is written around is a minor being served; accuracy is judged against this purpose and nothing else.
- **Annex III category**: 1(b)
- **Timeframe**: 2020-01-01T00:00:00Z to 2030-01-01T00:00:00Z

## 2. Activities carried out (Art. 6(2)(a))

- **Sectors**: Retail: unattended sale of age-restricted products
- **Testing**: carried out (attested runs [1, 2])

## 3. Requirements and obligations evaluated (Art. 6(2)(b))

In scope, as agreed in the sandbox plan:

- AI Act Art. 10 — Data governance for the held-out and stress sets
- AI Act Art. 12 — Automatic logging of decisions
- AI Act Art. 14 — Human oversight at the point of sale; guidance only
- AI Act Art. 15 — Accuracy and robustness
- AI Act Art. 4 bis — Special-category data for bias detection
- GDPR Art. 9 — Face images and group labels

Regulatory challenges the plan set out to examine (EUSAiR USF Annex XI):

- AI Act Art. 4 bis: Whether bias detection justifies processing skin-tone labels when synthetic faces cannot show the disparity.
- AI Act Art. 14: What human oversight means at an unattended point of sale.

Measured by the plan's tests, outcome per run:

| Test | Article | Runs |
|---|---|---|
| `accuracy_by_group` | 15 | 1: fail, 2: pass |
| `minors_accepted_by_group` | 10, 15 | 1: fail, 2: pass |
| `robustness` | 15 | not run |
| `adversarial_robustness` | 15 | not run |
| `fail_safe` | 15 | not run |
| `determinism` | 15 | not run |
| `decision_logging` | 12, 19 | 1: pass, 2: pass |

Objectives, against the tests the plan says evidence them:

- **minors_not_served** — met (`minors_accepted_by_group`, `accuracy_by_group`): Show that the system refuses minors at a rate the authority accepts, in every skin-tone band and sex, on data the provider has never seen.
- **stable_under_field_conditions** — not fully tested (`robustness`, `determinism`): Show that blur, low light, compression and the other plan perturbations do not raise the false-adult rate beyond the plan's limit, and that the same image gets the same decision.
- **resists_manipulation_and_fails_closed** — not fully tested (`adversarial_robustness`, `fail_safe`): Show that a customer who can only show the camera an image and read the answer cannot, within the plan's query budget, turn a refused minor into a sale, and that a covered lens, an empty aisle, a printed card or a frame the system was not built for is refused rather than approved. This is not a penetration test of the provider's system; that stays with the provider.
- **decisions_are_logged** — met (`decision_logging`): Show that every decision is logged with the fields Art. 12 needs.
- **human_oversight_design** — assessed by the authority (no test): Discuss with the authority how staff override a refusal at the point of sale. Assessed by the authority; no automated test measures it.

## 4. Completion (Art. 6(2)(c))

- **Completed**: yes, exit allowed by the gate at 2026-09-29T08:52:00.824Z (ledger seq 23)
- **Data keys destroyed**: ledger seq 24
- **Exit report due by**: 2026-11-29T08:52:00.824000+00:00 (two months after completion, draft implementing act Art. 6(4))

## 5. Evidence

- Ledger head: `sha256:89c4cf0a6b77cac0a6ec2ea14504b7db6d8c24d3b8ef017e36d7fcb0c9942ec4`
- Evidence bundle at generation: `sha256:fff8a8b2304dd9a47414f67ee3674b2a7072588bce2f005aec82ac9d58e76c88`
- Check the bundle offline with `histor verify <bundle>`.
