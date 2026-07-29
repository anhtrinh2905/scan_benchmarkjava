---
title: 'Ablation runner — harness vs static tool'
type: 'feature'
created: '2026-07-28'
status: 'done'
review_loop_iteration: 0
baseline_commit: '66f5464019f92d8835ea03cb121bf4f91449a0cf'
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `scripts/sweep.py` chỉ vặn nút hiệu năng *bên trong* một kiến trúc cố định (`harness + prompt`) và đã chạm diminishing returns — 5 variant đều 86–95% precision, 3.4–4.0M token. Nó không trả lời được: hiệu suất đến từ **LLM reasoning trong agent loop** hay từ **static analysis**, và cái nào cho ROI tốt hơn trên mỗi token.

**Approach:** Thêm `scripts/ablation.py` — sibling của `scripts/sweep.py`, cũng `import bench as bm` — chạy 3 kiến trúc khác nhau về **cơ chế discovery** (cộng một arm dẫn xuất) trên cùng tập test và ground truth, rồi xuất Pareto frontier + đề xuất arm thắng theo Youden/1M-token.

| Arm | Cấu hình | Vai trò |
|---|---|---|
| A `prompt_only` | `--tools none`, không `--triage`, `review_code` | Sàn dưới |
| B `harness` | `--tools navigation`, `--triage`, `review_code` | = baseline sweep |
| C `static` | Semgrep → `metis --command "triage <sarif>"` | LLM chỉ verify |
| `B_union_C` | Gộp offline SARIF của B và C | Dẫn xuất, **0 token** |

> Arm D (`harness + tree_sitter`) đã **bỏ** sau khi user duyệt plan ngày 2026-07-28: `tree_sitter.yaml` là `status: planned`, không có `implementation:` → `parse_engine_tools` từ chối. Tool active còn lại là `index`, nhưng nó cần embedding mà router không phục vụ (`openai` thiếu credential, `antigravity` không hỗ trợ embeddings).

## Boundaries & Constraints

**Always:**
- `scripts/ablation.py` là file MỚI. Không sửa `scripts/bench.py`/`scripts/sweep.py` — đã commit, đang chạy đúng.
- Dùng lại `bm.score_run`, `bm.aggregate`, `bm.load_ground_truth`, `bm.select_tests`, `bm.load_usage`, `bm.cwe_numbers`. `bm.aggregate` đã trả sẵn `fpr` + `youden`.
- `OUT_DIR = bm.ROOT/"results"/"ablation"`. Không ghi vào `results/sweep/`.
- Cache signature PHẢI gồm `tools`/`command`/`triage` + ruleset Semgrep. `scripts/sweep.py:146` thiếu → bê nguyên sẽ trả kết quả sai im lặng.
- Không tin exit code Metis (`entry.py:446-455` trả 0 cả khi lỗi) — verify SARIF tồn tại + parse được, như `scripts/bench.py:344-357`.
- Lệnh `triage` PHẢI có `--output-file <x>.sarif`; mặc định ghi đè in-place, sẽ phá SARIF gốc.
- Giữ guard đường dẫn không khoảng trắng (`scripts/bench.py:771-772`) — `entry.py:283` split `--command` bằng whitespace.

**Ask First:** đổi ruleset Semgrep khỏi `p/java` + `p/owasp-top-ten`; mọi thay đổi vào `scripts/bench.py`/`scripts/sweep.py`; nếu ước tính full run vượt ~2 giờ.

**Never:** LLM-judge (chấm chỉ theo `expectedresults-1.2.csv`); sửa `BenchmarkJava/` hay `metis/`; thêm arm ngoài các arm trên.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output | Error Handling |
|---|---|---|---|
| Happy path | 3 arm xong | `compare.{md,csv,json}`, cột Youden/1M, đánh dấu Pareto, in arm đề xuất | N/A |
| Semgrep thiếu CWE | `result.properties` rỗng; CWE ở `rule.properties.tags` | Inject `properties.cwe="CWE-22"` (chuỗi) qua lookup `ruleId`→rule, TRƯỚC triage và trước chấm | Rule không có tag CWE → giữ finding, `cwes=[]`, vào `off_target`, log số lượng |
| Arm lỗi giữa chừng | Arm thứ 3 hỏng | Ghi row lỗi, chạy tiếp arm còn lại, exit 1 | Arm ĐẦU lỗi → dừng cả run (lỗi cấu hình/auth) |
| Triage lại SARIF đã annotate | `properties.metisTriaged` đã có | Tách `semgrep.raw.sarif` ≠ `triaged.sarif`; không triage đè | Input đã triaged → `BenchError`, không âm thầm no-op |
| Arm A không triage | Thiếu `metisTriageStatus` | `status` default `"valid"` → strict == lenient; báo cáo ghi rõ | N/A |
| Semgrep 0 finding | SARIF hợp lệ, `results: []` | Chấm bình thường: mọi test → FN hoặc TN | N/A |

</frozen-after-approval>

## Code Map

- `scripts/bench.py` -- library gốc. Dùng `ROOT`, `METIS_DIR`, `BENCH_DIR`, `TESTCODE_DIR`, `BenchError`, `load_config`, `load_ground_truth`, `select_tests`, `score_run`, `aggregate`, `load_usage`, `cwe_numbers`, `_pct`, `_tail`, `_utc_now`. KHÔNG sửa.
- `scripts/sweep.py:90-343` -- khuôn mẫu để copy/adapt: `deep_merge`, `render_variant_yaml`, `include_paths_for`, `run_variant`, `extract_findings_by_test`, `score_variant`, `triage_precision`. KHÔNG sửa.
- `scripts/ablation.py` -- **FILE MỚI**, toàn bộ deliverable.
- `results/ablation/<arm>/` + `results/ablation/compare.{md,csv,json}` -- output (`results/` đã trong `.gitignore`).

## Tasks & Acceptance

**Execution:**
- [x] `scripts/ablation.py` -- `ARMS` (dict: `tools`, `command`, `triage`, `engine`, `note`) + `OUT_DIR` + `SEMGREP_RULESETS` -- một chỗ duy nhất định nghĩa ma trận thí nghiệm.
- [x] `scripts/ablation.py` -- `arm_command()` tham số hoá `--tools`/`--command`/`--triage` (scripts/sweep.py:171-177 hardcode); `arm_signature()` gồm các flag đó + ruleset -- chống cache sai.
- [x] `scripts/ablation.py` -- `run_semgrep()`: cwd=`BENCH_DIR` để URI tương đối đúng, giới hạn đúng tập file trong scope, ghi `semgrep.raw.sarif`.
- [x] `scripts/ablation.py` -- `normalize_semgrep_sarif()`: `ruleId` → `rule.properties.tags` → inject `result.properties.cwe`, ghi `semgrep.normalized.sarif` -- thiếu bước này arm C ra 0 on-target.
- [x] `scripts/ablation.py` -- `run_arm()`: nhánh review (A/B) và nhánh triage (C); verify sản phẩm thay vì exit code; thu `usage` TRƯỚC khi xoá `.work/`.
- [x] `scripts/ablation.py` -- `derive_union()`: gộp finding B ∪ C theo `(test, LỚP TƯƠNG ĐƯƠNG CWE`, dùng `bm.CWE_ALIASES`), chấm lại bằng `bm.score_run`. Khoá CWE chính xác đếm CWE-326 và CWE-327 thành hai lỗ hổng khác nhau và làm sai lệch chính con số mà arm này tồn tại để đo.
- [x] `scripts/ablation.py` -- `pareto_front()` + `build_report()`: cột `Arm | Youden(strict) | Youden(lenient) | Precision | Recall | FPR | Token | Phút | Youden/1M | Pareto`.
- [x] `scripts/ablation.py` -- argparse `--only/--sample/--force/--dry-run/--rescore/-y` khớp ngữ nghĩa sweep.py.
- [x] Chạy smoke `--sample 6`, rồi full `--sample 100`.

**Acceptance Criteria:**
- Given `--dry-run --sample 100`, when chạy, then in 3 lệnh arm + lệnh Semgrep, không gọi API và không ghi file kết quả.
- Given arm C xong, when đọc `results/ablation/static/triaged.sarif`, then mỗi result có cả `properties.cwe` (ta inject) lẫn `properties.metisTriageStatus` (Metis ghi), và `semgrep.raw.sarif` vẫn nguyên vẹn.
- Given chạy hai lần cùng tham số, when lần hai chạy, then mọi arm báo `[cache]`, token cộng thêm = 0.
- Given đổi `tools` của một arm trong `ARMS`, when chạy lại, then đúng arm đó cache hết hạn, các arm khác vẫn cache.
- Given 3 arm xong, when đọc `compare.md`, then mỗi arm có Youden/1M-token, tập Pareto được đánh dấu, và có đúng một dòng đề xuất arm thắng kèm lý do định lượng.
- ~~Given arm B và baseline sweep cùng `--sample 100`, then GT-precision/recall lệch ≤2 điểm phần trăm.~~ **BỎ** — `results/sweep/` chạy trên `cx/gpt-5.4`, model này đã biến mất khỏi router; ablation chạy trên `gcli/grok-build`. Khác model thì đối chiếu vô nghĩa.
- Given scope chấm điểm không có lấy một mẫu ÂM nào (mọi test đều vulnerable), when build báo cáo, then FPR/Youden/Pareto phải in `n/a` kèm cảnh báo, tuyệt đối không bịa số.

## Design Notes

`B_union_C` là arm dẫn xuất vì Metis CLI không có đường nạp seed finding từ SAST ngoài vào `review_code`. Gộp offline hai SARIF đã có cho đúng thông tin cần (hai cơ chế bổ sung hay trùng nhau) với chi phí 0.

Chuẩn hoá CWE là chỗ dễ hỏng nhất. `bm.cwe_numbers` chạy `re.findall(r"\d{1,4}", raw)` và trả `[]` nếu input không phải `str` → inject **chuỗi rút gọn**, không phải cả tag (tag đầy đủ kéo theo số rác từ mô tả; `list` bị trả `[]`):

```python
# tag: "CWE-22: Improper Limitation of a Pathname ... ('Path Traversal')"
ids = [m.group(1) for t in rule_tags if (m := re.match(r"(CWE-\d+)", str(t)))]
result.setdefault("properties", {})["cwe"] = ",".join(ids)   # -> "CWE-22"
```

## Verification

**Commands:**
- `python3 -c "import ast; ast.parse(open('scripts/ablation.py').read())"` -- không lỗi cú pháp
- `./scripts/ablation.py --dry-run --sample 100` -- in 3 lệnh arm + semgrep, exit 0, không tạo file trong `results/ablation/`
- `./scripts/ablation.py --sample 6 -y` -- 3 arm xong, `compare.md` tồn tại, exit 0
- `./scripts/ablation.py --sample 6 -y` (lần 2) -- mọi arm in `[cache]`, không gọi API
- `./scripts/ablation.py --sample 100 -y` -- `compare.md` đủ 4 dòng (3 arm + `B_union_C`), Youden KHÔNG còn `n/a`, có cột Pareto + dòng đề xuất
- `git status --short` -- `results/` không xuất hiện

**Manual checks:**
- `results/ablation/static/semgrep.normalized.sarif`: mọi result có `properties.cwe` dạng `CWE-\d+`; số rule thiếu CWE khớp con số script log ra.
- `results/ablation/compare.md`: arm A phải có strict == lenient (không triage). Khác nhau → logic status mặc định sai.

## Suggested Review Order

**Ma trận thí nghiệm — đọc cái này trước**

- Điểm vào: ba arm và cơ chế discovery của từng arm, một chỗ duy nhất định nghĩa cả thí nghiệm.
  [`scripts/ablation.py:105`](../../scripts/ablation.py#L105)

- Cố tình không có `deep_merge`/engine-override như `scripts/sweep.py`: mọi arm dùng chung `BASE_ENGINE` để chênh lệch chỉ đến từ kiến trúc.
  [`scripts/ablation.py:142`](../../scripts/ablation.py#L142)

**Chuẩn hoá CWE của Semgrep — chỗ dễ hỏng nhất**

- Semgrep để `result.properties` rỗng, CWE nằm ở `rule.properties.tags`; thiếu bước inject là arm C ra 0 on-target.
  [`scripts/ablation.py:373`](../../scripts/ablation.py#L373)

- Lớp tương đương CWE: khoá tuple chính xác đếm CWE-326 và CWE-327 thành hai lỗ hổng khác nhau.
  [`scripts/ablation.py:779`](../../scripts/ablation.py#L779)

- Gộp union theo lớp tương đương, kèm đếm `alias_matched` và `collapsed_*` để cột `findings` còn so được với arm nguồn.
  [`scripts/ablation.py:795`](../../scripts/ablation.py#L795)

**Chống kết quả sai âm thầm — nhóm quan trọng nhất**

- Không tin exit code của Metis (`entry.py:446-455` trả 0 cả khi lỗi); 0 token = mọi lời gọi LLM thất bại, trừ arm triage có 0 finding.
  [`scripts/ablation.py:557`](../../scripts/ablation.py#L557)

- Semgrep exit 0 vẫn có thể lỗi từng phần; `--quiet` che stderr nên phải đọc `executionSuccessful`/`toolExecutionNotifications`.
  [`scripts/ablation.py:436`](../../scripts/ablation.py#L436)

- SARIF triaged dở (bị kill giữa checkpoint) sẽ mặc định thành `valid` và thổi phồng FP; chặn ở cả cache và rescore.
  [`scripts/ablation.py:465`](../../scripts/ablation.py#L465)

- Chữ ký cache phải gồm CLI flag, version Metis/Semgrep và `NORMALIZER_VERSION` — thiếu là cache trả kết quả sai.
  [`scripts/ablation.py:264`](../../scripts/ablation.py#L264)

- Bump khi sửa logic rút CWE, để kết quả arm C cũ hết hạn thay vì được dùng lại kèm CWE sai.
  [`scripts/ablation.py:71`](../../scripts/ablation.py#L71)

- `--rescore` phải kiểm `tests_digest`: chấm lại SARIF của scope khác biến 94 test thành FN/TN.
  [`scripts/ablation.py:1180`](../../scripts/ablation.py#L1180)

- Retry vì Semgrep tải 560 rule qua mạng; log ghi APPEND để không xoá mất bằng chứng lần hỏng.
  [`scripts/ablation.py:306`](../../scripts/ablation.py#L306)

**Báo cáo — phải tự nói ra khi nó không đầy đủ**

- Cảnh báo chạy một phần, ghi chú union bị bỏ, và làm phẳng text lỗi nhiều dòng để CSV không vỡ.
  [`scripts/ablation.py:952`](../../scripts/ablation.py#L952)

- Không kết luận khi chỉ một arm chấm được, khi mọi Youden âm, và ưu tiên arm rẻ hơn khi hoà điểm.
  [`scripts/ablation.py:900`](../../scripts/ablation.py#L900)

- Pareto: arm không bị arm nào khác vừa cao điểm hơn vừa rẻ hơn.
  [`scripts/ablation.py:877`](../../scripts/ablation.py#L877)
