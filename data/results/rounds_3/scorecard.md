# Metis vs OWASP BenchmarkJava — scorecard

| | |
|---|---|
| Thời điểm | 2026-07-28T02:26:38.801812+00:00 |
| Scan model | `cx/gpt-5.4` |
| Metis | v1.5.0 (git 66f5464) |
| Triage | bật |
| Số test × lặp | 100 × 1 = 100 lần scan |
| Tập test | 100 test: `BenchmarkTest00001` → `BenchmarkTest00100` |

## Chi phí

| Chỉ số | Giá trị |
|---|---:|
| Findings (thô) | **124** |
| Wall-clock | **65.8 phút** (3946s) |
| Metis duration (native) | 62.7 phút |
| Token | **3.58M** (3.40M in / 0.175M out) |

## Precision / Recall (đối chiếu ground truth)

| Chỉ số | strict | lenient |
|---|---:|---:|
| TP | 71 | 71 |
| FP | 1 | 1 |
| FN | 4 | 4 |
| TN | 24 | 24 |
| **Precision** | **98.6%** | **98.6%** |
| **Recall (TPR)** | **94.7%** | **94.7%** |
| FPR | 4.0% | 4.0% |
| Youden (TPR−FPR) | 90.7% | 90.7% |

Đơn vị là **mỗi file test**, không phải mỗi finding: một file có 3 finding vẫn chỉ tính một TP. Finding off-target (CWE khác CWE kỳ vọng) không vào TP/FP, chỉ được đếm riêng như nhiễu.

**strict** = `inconclusive` tính là *vẫn báo cáo* (thứ dev thực sự phải đọc). **lenient** = `inconclusive` tính là *đã loại* (kịch bản tốt nhất). Chênh lệch giữa hai cột = mức độ do dự của model.

## Theo category

| Category | Test | TP | FP | FN | TN | Recall | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| weakrand | 18 | 13 | 0 | 0 | 5 | 100.0% | 0.0% | 100.0% |
| sqli | 15 | 14 | 0 | 0 | 1 | 100.0% | 0.0% | 100.0% |
| hash | 13 | 5 | 0 | 2 | 6 | 71.4% | 0.0% | 71.4% |
| crypto | 12 | 9 | 1 | 0 | 2 | 100.0% | 33.3% | 66.7% |
| pathtraver | 12 | 9 | 0 | 1 | 2 | 90.0% | 0.0% | 90.0% |
| cmdi | 10 | 7 | 0 | 0 | 3 | 100.0% | 0.0% | 100.0% |
| xss | 8 | 8 | 0 | 0 | 0 | 100.0% | n/a | n/a |
| trustbound | 5 | 2 | 0 | 1 | 2 | 66.7% | 0.0% | 66.7% |
| securecookie | 4 | 1 | 0 | 0 | 3 | 100.0% | 0.0% | 100.0% |
| ldapi | 3 | 3 | 0 | 0 | 0 | 100.0% | n/a | n/a |

_Cột strict. Bảng đầy đủ từng test nằm trong `bench_summary.json` (`ground_truth.per_test`)._

## Ca sai (5)

| Test | Loại | CWE | Ground truth | run | strict | lenient | on-target | do dự |
|---|---|---|---|---:|---|---|---:|---:|
| `BenchmarkTest00003` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00059` | crypto | 327 | an toàn | 1 | **FP** | FP | 1 | 0 |
| `BenchmarkTest00061` | pathtraver | 22 | có lỗ hổng | 1 | **FN** | FN | 1 | 0 |
| `BenchmarkTest00074` | hash | 328 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |
| `BenchmarkTest00098` | trustbound | 501 | có lỗ hổng | 1 | **FN** | FN | 0 | 0 |

**FN** = bỏ sót lỗ hổng thật. **FP** = báo nhầm trên file an toàn.

## Độ ổn định

_Chạy 1 lần — không đo được. Dùng `--repeat 3` để đánh giá._

## Chi tiết finding (chỉ các ca sai)

### `BenchmarkTest00003` — hash, CWE-328, có lỗ hổng

- **run 1** · dòng 36 · CWE `CWE-922` (off-target) · severity `Medium` · triage **valid**
  - Sensitive secret stored directly in a client-side cookie
  - _triage:_ Verdict: Valid; the servlet creates a cookie with literal value "someSecret" and sends it to the client. Evidence: `new javax.servlet.http.Cookie("BenchmarkTest00003", "someSecret")` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:37 is configured then emitted via `response.addCookie(userCookie)` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:43; `setSecure`/`setHttpOnly` only add flags at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:39 and src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:40. Gap: none.
- **run 1** · dòng 72 · CWE `CWE-759` (off-target) · severity `High` · triage **valid**
  - Password-like value hashed without a salt before storage
  - _triage:_ Verdict: The finding is valid because the code hashes cookie-derived input with `MessageDigest` and stores the resulting Base64 digest without any salt. Evidence: Cookie value flows into `param` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:57 and src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:61, is converted to bytes and hashed via `MessageDigest.getInstance`/`md.digest` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:72 and src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:75, and the digest is written to `passwordFile.txt` as `hash_value=` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java:72. Gap: none.

### `BenchmarkTest00059` — crypto, CWE-327, an toàn

- **run 1** · dòng 83 · CWE `CWE-327` (on-target) · severity `High` · triage **valid**
  - Insecure default cipher mode uses AES in ECB mode
  - _triage:_ Verdict: valid because the code defaults `cryptoAlg2` to `AES/ECB/PKCS5Padding` and immediately instantiates that cipher. Evidence: `benchmarkprops.getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding")` sets the insecure default at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00059.java:83, and `javax.crypto.Cipher.getInstance(algorithm)` consumes it at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00059.java:84. Gap: none.
- **run 1** · dòng 42 · CWE `CWE-346` (off-target) · severity `Medium` · triage **valid**
  - Cookie domain derived from user-controlled request URL/Host data
  - _triage:_ Verdict: Valid; the cookie domain is set directly from the request URL host. Evidence: `userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost())` uses `request.getRequestURL()` as the source and immediately applies `.getHost()` to `setDomain` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00059.java:42, while the cookie is then sent via `response.addCookie(userCookie)` at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00059.java:43. Gap: none.

### `BenchmarkTest00061` — pathtraver, CWE-22, có lỗ hổng

- **run 1** · dòng 56 · CWE `CWE-22` (on-target) · severity `High` · triage **invalid**
  - Path traversal via cookie-controlled filesystem path
  - _triage:_ Verdict: invalid; cookie value is read but not used to control the resulting filesystem path because `new java.io.File(bar, "/Test.txt")` supplies an absolute child path. Evidence: cookie flows into `param` at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00061.java:60`, into `bar` via reversible Base64 encode/decode at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00061.java:68`, then file creation uses absolute `"/Test.txt"` at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00061.java:75`, followed by `exists()` on that file at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00061.java:85`. Gap: none.

### `BenchmarkTest00074` — hash, CWE-328, có lỗ hổng

- **run 1** · dòng 36 · CWE `CWE-798` (off-target) · severity `High` · triage **valid**
  - Hard-coded secret value stored in a cookie
  - _triage:_ Verdict: The finding is valid because the servlet hard-codes the cookie value `someSecret` and sends it to the client. Evidence: `doGet` constructs `new javax.servlet.http.Cookie("BenchmarkTest00074", "someSecret")` and adds it to the response at src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00074.java:37 and src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00074.java:43. Gap: none.
- **run 1** · dòng 42 · CWE `CWE-346` (off-target) · severity `Medium` · triage **valid**
  - Cookie domain derived from untrusted request host
  - _triage:_ Verdict: Cookie domain is derived directly from request URL host without validation, so the finding is supported. Evidence: `BenchmarkTest00074.doGet` builds `userCookie`, sets path from request data, then sets domain from `new java.net.URL(request.getRequestURL().toString()).getHost()` before `response.addCookie(userCookie)` at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00074.java:41`, `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00074.java:42`, `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00074.java:43`. Gap: none.

### `BenchmarkTest00098` — trustbound, CWE-501, có lỗ hổng

- **run 1** · dòng 54 · CWE `CWE-602` (off-target) · severity `High` · triage **valid**
  - Untrusted cookie value is used as a session user identifier
  - _triage:_ Verdict: Valid; client cookie value is read, only URL-decoded and HTML-escaped, then stored in session key `userid`. Evidence: `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00098.java:54`, `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00098.java:60`, `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00098.java:66`, `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00098.java:69` show cookie input flowing into `request.getSession().putValue("userid", bar)`; `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00098.java:37` only shows the app also sets that cookie, not server-side validation on read. Gap: none.

