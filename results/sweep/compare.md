# So sánh sweep Metis

_Sinh lúc 2026-08-01T15:10:52.498524+00:00_

| Variant | Thời gian (phút) | Total token | Findings | Triage-prec | GT-precision | GT-recall |
|---|---:|---:|---:|---:|---:|---:|
| workers_10 (max_workers 5 -> 10 (nút THỜI GIAN)) | 20.9 | 3810741 | 118 | 99.2% | 91.4% | 85.3% |

> Precision/recall tính từ ground truth (expectedresults-1.2.csv), cột strict (`inconclusive` = vẫn tính là báo cáo). Không dùng LLM-judge.

