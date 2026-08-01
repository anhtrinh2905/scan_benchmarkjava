# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-08-01T14:47:05.313053+00:00 |
| Scan model | `deepseek-v4-pro` |
| Metis | v1.5.0 (git 0d6673a) |
| Triage | bật |
| Số test × lặp | 100 × 1 = 100 lần scan |
| Tập test | 100 test: `BenchmarkTest00001` → `BenchmarkTest00100` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **1** |
| Wall-clock | **103.4 phút** (6206s) |
| Metis duration (native) | 1.0 phút |
| Token | **0.03M** (0.03M in / 0.003M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 1 | 1 |
| FP | 0 | 0 |
| FN | 74 | 74 |
| TN | 25 | 25 |
| **Precision** | **100.0%** | **100.0%** |
| **Recall (TPR)** | **1.3%** | **1.3%** |
| FPR | 0.0% | 0.0% |
| Youden (TPR−FPR) | 1.3% | 1.3% |

Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào TP/FP, chỉ được đếm riêng như nhiễu.

**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). **lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). Chênh lệch giữa hai cột = mức độ do dự của model.

## Theo category

| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| weakrand | 18 | 0 | 0 | 13 | 5 | 0.0% | 0.0% | 0.0% |
| sqli | 15 | 0 | 0 | 14 | 1 | 0.0% | 0.0% | 0.0% |
| hash | 13 | 0 | 0 | 7 | 6 | 0.0% | 0.0% | 0.0% |
| crypto | 12 | 0 | 0 | 9 | 3 | 0.0% | 0.0% | 0.0% |
| pathtraver | 12 | 1 | 0 | 9 | 2 | 10.0% | 0.0% | 10.0% |
| cmdi | 10 | 0 | 0 | 7 | 3 | 0.0% | 0.0% | 0.0% |
| xss | 8 | 0 | 0 | 8 | 0 | 0.0% | n/a | n/a |
| trustbound | 5 | 0 | 0 | 3 | 2 | 0.0% | 0.0% | 0.0% |
| securecookie | 4 | 0 | 0 | 1 | 3 | 0.0% | 0.0% | 0.0% |
| ldapi | 3 | 0 | 0 | 3 | 0 | 0.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (74)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00002` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00003` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00004` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00005` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00006` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00007` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00008` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00011` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00012` | ldapi | 90 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00013` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00014` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00015` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00017` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00018` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00019` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00020` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00021` | ldapi | 90 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00023` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00024` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00025` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00026` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00027` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00028` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00029` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00030` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00031` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00032` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00033` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00034` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00035` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00036` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00037` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00038` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00039` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00040` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00041` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00043` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00044` | ldapi | 90 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00045` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00046` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00047` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00048` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00049` | xss | 79 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00050` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00053` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00055` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00056` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00057` | crypto | 327 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00060` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00061` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00062` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00065` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00066` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00067` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00068` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00070` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00071` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00073` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00074` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00077` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00078` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00079` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00080` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00081` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00082` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00083` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00084` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00085` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00086` | weakrand | 330 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00087` | securecookie | 614 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00091` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00092` | cmdi | 78 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00098` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00100` | sqli | 89 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00002` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00003` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00004` — trustbound, CWE-501, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00005` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00006` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00007` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00008` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00011` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00012` — ldapi, CWE-90, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00013` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00014` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00015` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00017` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00018` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00019` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00020` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00021` — ldapi, CWE-90, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00023` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00024` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00025` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00026` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00027` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00028` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00029` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00030` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00031` — trustbound, CWE-501, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00032` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00033` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00034` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00035` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00036` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00037` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00038` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00039` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00040` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00041` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00043` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00044` — ldapi, CWE-90, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00045` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00046` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00047` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00048` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00049` — xss, CWE-79, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00050` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00053` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00055` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00056` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00057` — crypto, CWE-327, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00060` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00061` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00062` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00065` — pathtraver, CWE-22, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00066` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00067` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00068` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00070` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00071` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00073` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00074` — hash, CWE-328, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00077` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00078` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00079` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00080` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00081` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00082` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00083` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00084` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00085` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00086` — weakrand, CWE-330, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00087` — securecookie, CWE-614, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00091` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00092` — cmdi, CWE-78, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00098` — trustbound, CWE-501, có lỗ hổng

_Metis không báo finding nào cho file này._

### `BenchmarkTest00100` — sqli, CWE-89, có lỗ hổng

_Metis không báo finding nào cho file này._

