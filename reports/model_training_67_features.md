# Random Forest retraining report: 67 flow features

## Artifacts

- Active model: `ml/rf_model.pkl` (160 trees, 67 CICFlowMeter features).
- Candidate copy: `reports/model_candidates/rf_model_67_candidate.pkl`.
- Previous 25-feature model backup: `reports/model_backups/rf_model_25_features_before_expansion.pkl`.

The 67-column order is shared by `ids/detectors/ml/features.py`, the runtime
feature adapter, the CSV normalizer, and the trainer. Both the loaded model and
runtime smoke prediction were checked for the same 67 names in the same order.

## Training rows after label normalization

| Class | Flow count |
|---|---:|
| BENIGN | 1,656,430 |
| DoS Hulk | 231,073 |
| DoS GoldenEye | 10,293 |
| DoS slowloris | 5,796 |
| DoS Slowhttptest | 5,499 |
| Web Attack - Brute Force | 1,756 |
| XSS | 731 |
| Sqli | 55 |
| **Total** | **1,911,633** |

Heartbleed rows are excluded by the existing dataset normalizer. SQLi remains
very underrepresented, which limits what any supervised model can learn about
that class.

## Same-split comparison

Both schemas were evaluated using the same stratified 75/25 split and the same
80-tree Random Forest configuration. Values below are rounded as printed by
scikit-learn.

| Class | 25-feature recall | 67-feature recall | Holdout count |
|---|---:|---:|---:|
| BENIGN | 1.00 | 1.00 | 414,108 |
| DoS GoldenEye | 0.99 | 0.99 | 2,573 |
| DoS Hulk | 1.00 | 1.00 | 57,768 |
| DoS Slowhttptest | 0.99 | 0.99 | 1,375 |
| DoS slowloris | 0.99 | 1.00 | 1,449 |
| Sqli | 0.14 | 0.14 | 14 |
| Web Attack - Brute Force | 0.83 | 0.83 | 439 |
| XSS | 0.32 | 0.30 | 183 |

The expanded model did not improve SQLi or XSS recall on this random holdout.
Its macro recall/F1 stayed about 0.78/0.80. The high overall accuracy is
dominated by the large BENIGN class and should not be used alone to claim
attack coverage.

## Cross-dataset check

The expanded model trained on CIC-IDS-2017 and evaluated on the Thursday
CIC-IDS-2018 web-attack file had recall 0.89 for BENIGN, 0.01 for Web Attack -
Brute Force, and 0.00 for XSS and Sqli. This is a substantial dataset/capture
shift. That file has no DoS examples, so it does not measure DoS generalization.

## Runtime interpretation

The live alert threshold remains `ML_ALERT_THRESHOLD = 0.15`. It can surface
some BENIGN argmax flows using their highest attack probability, but the
backstop can also assign the wrong attack subtype. The new features are now
present in packet parsing, bidirectional flow accumulation, training, and
inference. This training run does not prove zero missed attacks; lab-specific
labeled flows, especially SQLi and XSS, are still needed to evaluate and improve
recall.
