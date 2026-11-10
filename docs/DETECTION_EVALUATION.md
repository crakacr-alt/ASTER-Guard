# Detection accuracy: evidence ledger

## Available automated data
\`RiskEvaluationMatrixTest\` runs **synthetic boolean feature vectors** through a transparent risk scoring system. It helps prevent code regressions but does **not** measure real malware/benign false-positive rates or unseen-threat coverage. The synthetic classification labels are not malware ground truth.

## Required for a validated antimalware product
- Independently sampled *legally obtained* benign APK corpus, categorized by purpose and Android version.
- Lab-controlled malicious APK set with published hashes, family labels, age and representative samples; never include working malicious executables in a public repo.
- Deduplicated package/signing clusters across training/testing to prevent leakage.
- Freeze threat rules before testing and include genuinely unseen holdouts.
- Compute TP/FP/FN/TN, precision, recall, FPR with confidence intervals; publish per-family results and failure examples.
- Differential testing against Android Play Protect and third-party antivirus engines only under approved lab conditions. Do not claim superior accuracy without evidence.
- Ensure high-risk signals are explanations, **not** automatic uninstall/block verdicts.

### Current status
No real-world corpus results have been produced. This project is a security analyzer and privacy utility with heuristic flags, not a proven malware detector.
