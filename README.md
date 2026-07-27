# Scan benchmark java

## Dataset 

- Repo đích để quét: [BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) - đây là 1 repo thuộc OWASP và đã **có grounding truth** cụ thể.

- Mô tả:
    - BenchmarkJava bao gồm 2740 testcases riêng lẻ
    - Mỗi testcase là 1 đoạn code chứa finding cần tìm, finding đó có thể là TP hoặc FP để bẫy model

- Trên phạm vi kiểm thử thì em chỉ chạy trên **100 testcases**

## Thực hiện

- Công cụ quét: [Metis (ARM)](https://github.com/arm/metis)

- Chạy lần 1: Chạy trên metis baseline, kết qủa:
- Chạy lần 2: Chạy để tìm tham số tối ưu
- Chạy lần 3: Sửa prompt 
- Chạy lần 4: Thêm Harness