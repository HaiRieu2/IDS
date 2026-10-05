# Random Forest retraining report: 67 flow features

## Artifacts

- Active model: `ml/rf_model.pkl` (160 trees, 67 CICFlowMeter features).
- Candidate copy from the HTTP DoS label merge: `reports/model_candidates/rf_model_http_dos_labels.pkl`.
- Previous 25-feature model backup: `reports/model_backups/rf_model_25_features_before_expansion.pkl`.

The 67-column order is shared by `ids/detectors/ml/features.py`, the runtime
feature adapter, the CSV normalizer, and the trainer. Both the loaded model and
runtime smoke prediction were checked for the same 67 names in the same order.

## Training rows after label normalization

| Class | Flow count |
|---|---:|
| BENIGN | 1,656,430 |
| HTTP Flood (DoS Hulk + DoS GoldenEye) | 241,366 |
| HTTP slow (DoS slowloris + DoS Slowhttptest) | 11,295 |
| Web Attack - Brute Force | 1,756 |
| XSS | 731 |
| Sqli | 55 |
| **Total** | **1,911,633** |

Heartbleed rows are excluded by the existing dataset normalizer. SQLi remains
very underrepresented, which limits what any supervised model can learn about
that class.

## Merged-label model evaluation

The merged-label model was evaluated using a stratified 75/25 split and an
80-tree Random Forest. Values below are rounded as printed by scikit-learn.

| Class | Raw argmax recall | Live-threshold recall | Holdout count |
|---|---:|---:|---:|
| BENIGN | 1.00 | 1.00 | 414,108 |
| HTTP Flood | 1.00 | 1.00 | 60,341 |
| HTTP slow | 1.00 | 1.00 | 2,824 |
| Sqli | 0.29 | 0.36 | 14 |
| Web Attack - Brute Force | 0.82 | 0.86 | 439 |
| XSS | 0.33 | 0.37 | 183 |

The live-threshold report uses `ML_ALERT_THRESHOLD = 0.15`. Overall binary
attack recall was 0.9998 (63,788/63,801) and BENIGN false-positive rate was
0.0007 (307/414,108) on this random holdout. These results can be optimistic
because related capture traffic is split randomly; high overall accuracy is
dominated by BENIGN and should not be used alone to claim attack coverage.

## Cross-dataset check

The merged-label model trained on CIC-IDS-2017 and evaluated on the Thursday
CIC-IDS-2018 web-attack file had raw-argmax recall 0.96 for BENIGN, 0.01 for
Web Attack - Brute Force, and 0.00 for XSS and Sqli. The file has no HTTP Flood
or HTTP slow examples, so it does not measure generalization for those classes.
With the runtime threshold backstop enabled, binary attack recall was 0.7182
and BENIGN false-positive rate was 0.1356 on this source-shift check.

## Runtime interpretation

The live alert threshold remains `ML_ALERT_THRESHOLD = 0.15`. It can surface
some BENIGN argmax flows using their highest attack probability, but the
backstop can also assign the wrong attack subtype. The new features are now
present in packet parsing, bidirectional flow accumulation, training, and
inference. This training run does not prove zero missed attacks; lab-specific
labeled flows, especially SQLi and XSS, are still needed to evaluate and improve
recall.
