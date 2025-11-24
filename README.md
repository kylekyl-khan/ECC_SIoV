# SIOV Demo with MIRACL Core (C)

這個專案是一個「身份為基礎的簽章 / 驗證」(SIOV, Signatures In the Internet of Vehicles) 示範程式。

目標是簡單演示相關密碼學流程：
- 編譯並執行 SIOV demo 程式
- 觀察簽章與驗證大致在做什麼
- 用腳本快速進行效能測試

底層使用 [MIRACL Core](https://github.com/miracl/core) 提供的 BN254 配對友善曲線來實作群運算與配對。

> ⚠️ **重要說明：核心演算法未收錄於此專案**
>
> - 真正研究中使用的核心 SIOV 演算法與協定設計，因為仍有「保密」與「尚未公開發表」的考量
> - **詳細的核心演算法設計並未在此程式碼庫中公開**
> - 目前專案中實作的僅為 **示範與教學用途的版本（demo algorithms）**，用來展示典型的簽章、驗證與批次驗證流程與效能量測方式；不代表最終的研究成果，也不應視為正式的協定規格或參考實作。

---

## 基本概念

這個專案主要示範基本的簽章與驗證流程：

- **簽章**：持有私鑰的一方對訊息產生簽章，用來證明「這個訊息是我發出的」。
- **驗證**：其他人利用公開資訊與簽章，確認簽章是否有效。
- **批次驗證**：把多筆簽章一次驗證，通常比逐筆驗證更有效率。

在這個 demo 中，我們會：
- 產生一些「車輛」的身份與金鑰
- 幫訊息產生簽章
- 驗證這些簽章是否正確
- （可選）把每次驗證用到的配對算式印出來，方便理解與除錯

---

## 系統需求

建議環境（開發與測試以此為主）：

- Ubuntu 22.04（也可在 Windows 上用 WSL）
- C 編譯器（`gcc` 或 `clang` 皆可）
- Python 3（用來跑 benchmark 腳本）
- MIRACL Core C 原始碼（BN254 曲線的實作）

---

## 下載 MIRACL Core

在專案根目錄底下，建議將 MIRACL Core 放在 `third_party/miracl-core` 中。

### 1. 取得 MIRACL Core 原始碼

```bash
git clone https://github.com/miracl/core third_party/miracl-core
```

### 2. 編譯 MIRACL Core (C 版)

請依 MIRACL 官方文件編譯 C 版程式庫。  
本專案預期以下路徑存在：

- 靜態函式庫（library）：
  - `third_party/miracl-core/c/lib/libcore.a`
- 標頭檔（headers）：
  - `third_party/miracl-core/c/include`

只要 MIRACL 的編譯結果放在上述位置，專案的 `Makefile` 就能找到它。

---

## 如何編譯這個專案

在專案根目錄執行：

```bash
make
```

成功後會在 `bin/` 資料夾產生主要執行檔：

- `bin/siov`

---

## 如何執行範例

編譯完成後，可以用以下指令試跑：

```bash
# 產生 50 筆簽章並驗證，不輸出追蹤資訊
./bin/siov --count 50 --verify on --trace off

# 產生 10 筆簽章並驗證，同時印出配對追蹤資訊
./bin/siov --count 10 --verify on --trace on
```

常用參數說明：

- `--count N`：要產生、驗證幾筆簽章
- `--verify on/off`：是否在產生簽章後立即做驗證
- `--trace on/off`：是否印出每次驗證用到的配對算式（適合教學 / 除錯）

---

## 使用 benchmark 腳本量測效能

專案中提供了一個簡單的 Python 腳本，用來多次重複執行，產生 CSV 格式的時間統計，方便之後用 Excel / pandas 繪圖或分析。

在專案根目錄執行：

```bash
python3 scripts/benchmark.py --repeat 10 --count 100
```

主要參數說明：

- `--repeat R`：重複執行 `siov` 命令 R 次
- `--count N`：每次執行 `siov` 時使用 `--count N`
- 輸出：一個含有執行時間等欄位的 CSV 檔案（路徑與欄位名稱可在腳本中查看）

---

## 曲線與型別（給想看細節的人）

這個專案使用 MIRACL Core 的 **BN254** 配對友善曲線。  
在 `src/siov_miracl.c` 中，有一些對 MIRACL 型別的包裝：

- G1 群點：`ECP_BN254`
- G2 群點：`ECP2_BN254`
- 配對目標群（GT）：`FP12_BN254`
- 大整數標量：`BIG_256_56`

透過這些型別，我們實作：

- 金鑰產生
- 簽章生成
- 單筆與批次驗證
- 配對運算的追蹤輸出（可選）

這裡的實作以可讀性與示範為主，不代表完整或最佳化的實務部署版本。

---

## 專案目錄結構

專案大致分為幾個部分：

- `include/`  
  專案公開的標頭檔。例如 SIOV 的 API 介面、MIRACL 包裝介面等。

- `src/`  
  C 語言實作：
  - `main.c`：命令列介面（CLI）與參數解析
  - `siov.c`：SIOV 相關核心邏輯（demo 版）
  - `siov_miracl.c`：MIRACL Core 的包裝與曲線運算
  - `siov_trace.c`：追蹤與除錯輸出相關的函式

- `scripts/benchmark.py`  
  使用 CLI 程式多次執行並輸出 CSV 的小工具，用來做效能評估。

- `third_party/miracl-core/`  
  外部相依的 MIRACL Core 原始碼／函式庫（不包含在本 repo 內，由使用者自行 clone）。

---

## 附註與限制

- 本專案採用的是 **示範用演算法與流程（demo implementation）**，不等同於實際研究中的完整協定與核心設計。
- 研究中實際使用的核心演算法來自指導教授的論文，且可能在未來修改後用於正式發表，因此目前不在此程式碼庫中公開。
- cryptographic 協定與實作細節刻意保持「偏簡化、偏直覺」，方便閱讀與教學。
- 若要用於實際安全場景，請務必：
  - 重新檢視協定安全性與設計細節
  - 對實作做完整的安全審查
  - 考慮旁路攻擊防護、金鑰管理、亂數品質等議題

---

## 我可以從哪裡開始看程式碼？

建議以下順序：

1. 看 [`src/main.c`](src/main.c)  
   了解 CLI 如何呼叫 SIOV demo 流程。

2. 看 [`src/siov.c`](src/siov.c)  
   了解簽章、驗證、批次驗證的大致流程（demo 版協定）。

3. 看 [`src/siov_miracl.c`](src/siov_miracl.c)  
   如果你對 MIRACL 或椭圓曲線有興趣，可以看到如何映射到 BN254 型別與 API。

4. 開啟 `--trace on` 試跑  
   一邊看終端機輸出的配對算式，一邊對照程式碼，加深對流程的理解。

歡迎依照需求修改、實驗不同參數，或將此專案作為後續研究 / 教學的起點。
