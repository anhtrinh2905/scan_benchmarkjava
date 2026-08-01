# So sánh sweep Metis

_Sinh lúc 2026-08-01T03:01:05.535505+00:00_

| Variant | Thời gian (phút) | Total token | Findings | Triage-prec | GT-precision | GT-recall |
|---|---:|---:|---:|---:|---:|---:|
| baseline ((không đổi gì) — mốc so sánh) | 0.5 | 0 | 0 | n/a | n/a | 0.0% |
| workers_10 (max_workers 5 -> 10 (nút THỜI GIAN)) | 0.3 | 0 | 0 | n/a | n/a | 0.0% |
| reach_1 (reachability_max_paths_per_sink 3 -> 1 (nút TOKEN)) | 0.5 | 0 | 0 | n/a | n/a | 0.0% |

> Precision/recall tính từ ground truth (expectedresults-1.2.csv), cột strict (`inconclusive` = vẫn tính là báo cáo). Không dùng LLM-judge.

