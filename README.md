# SSL 憑證監控工具說明手冊

## 1. 簡介
此工具用於自動檢查多個網站/服務的 SSL/TLS 憑證到期狀態與安全性，功能包括：

- 憑證到期日檢查  
- TLS 版本、簽章算法、公鑰長度檢查  
- CN/SAN 一致性檢查  
- 自簽憑證檢查  
- 安全建議 (Security Advice)  
- 多執行緒加速檢查  
- Excel 報表輸出  
- 郵件通知（附 Excel 附件）  
- 監控模式返回狀態碼（0:正常, 2:警告/錯誤）  

---

## 2. 系統需求

- **作業系統**：Linux / macOS / Windows  
- **Python 版本**：3.10+（建議 3.11）  
- **必須套件**：

```bash
pip install cryptography pandas openpyxl
```

- 可選套件（依 SMTP 功能需求）：

```bash
pip install secure-smtplib
```

---

## 3. 安裝 Python

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

### macOS

```bash
brew install python
```

### Windows

1. 下載官方安裝包：[Python 官方網站](https://www.python.org/downloads/)
2. 安裝時勾選 **Add Python to PATH**  

---

## 4. 目錄結構

```
ssl_check/
├── check_certs.py       # 主程式
├── config.json          # 設定檔
├── hosts.txt            # 主機清單
├── cert_report.xlsx     # 檢查結果 (執行後生成)
```

---

## 5. config.json 說明

```json
{
  "notify_before_days": 30,
  "verify_ssl": false,
  "max_threads": 20,
  "connect_timeout": 6,
  "log_file": "cert_check.log",
  "log_level": "INFO",
  "email": {
    "enabled": true,
    "smtp_server": "127.0.0.1",
    "smtp_port": 25,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "cert-check@example.com",
    "smtp_auth": false,
    "use_starttls": false,
    "to": ["admin@example.com"]
  },
  "slack": {
    "enabled": false,
    "webhook_url": ""
  }
}
```

### 主要參數

| 參數 | 說明 |
|------|------|
| notify_before_days | 提前通知天數，低於此值顯示 ALERT |
| verify_ssl | 是否驗證憑證完整性 (True/False) |
| max_threads | 多執行緒數量，加快大量主機檢查 |
| connect_timeout | 連線逾時時間（秒） |
| log_file | 日誌檔名 |
| log_level | 日誌等級（INFO/WARNING/ERROR） |
| email.enabled | 是否啟用郵件通知 |
| email.smtp_server | SMTP 伺服器地址 |
| email.smtp_port | SMTP 埠號 |
| email.smtp_user | SMTP 帳號 |
| email.smtp_password | SMTP 密碼 |
| email.smtp_from | 寄件人地址 |
| email.smtp_auth | 是否啟用 SMTP 認證 |
| email.use_starttls | 是否啟用 STARTTLS |
| email.to | 收件人清單 |
| slack.enabled | 是否啟用 Slack 通知（預留） |
| slack.webhook_url | Slack Webhook URL（預留） |

---

## 6. hosts.txt 說明

每行一個主機，可選擇指定端口（預設 443）：

```
example.com
api.example.com:8443
```

註解行以 `#` 開頭：

```
# 測試主機
test.example.com
```

---

## 7. 執行方式

### 7.1 基本檢查（非監控模式）

```bash
python3 check_certs.py
```

- 生成 Excel 報表  
- 依設定寄送郵件（若啟用）  
- CLI 顯示檢查結果  

### 7.2 監控模式（適合排程或監控系統）

```bash
python3 check_certs.py --monitor
```

- 有憑證過期/警告時，返回狀態碼 `2`  
- 全部正常返回 `0`  
- 可配合 Cron / CI/CD 自動監控  

### 7.3 強制寄送郵件

```bash
python3 check_certs.py --force-mail
```

- 即使沒有警告，也會寄送報表  

---

## 8. Excel 報表欄位說明

| 欄位 | 說明 |
|------|------|
| Host | 主機名稱 |
| Port | 埠號 |
| Expiry(Local) | 憑證到期日（本地時間） |
| Days Left | 剩餘天數 |
| Status | OK / ALERT |
| TLS Version | TLS/SSL 協定版本 |
| Signature | 簽章算法 |
| Key Size | 金鑰長度 |
| Security Advice | 資安建議摘要 |

---

## 9. 資安建議摘要

- **憑證即將到期**：立即更新憑證  
- **TLS 版本過舊 (SSLv3/TLS1.0/1.1)**：升級至 TLS1.2 或 TLS1.3  
- **過舊簽章 (SHA1/MD5)**：改用 SHA256+RSA/EC  
- **金鑰過短 (<2048)**：重新生成長度 ≥2048 的金鑰  
- **CN/SAN 不符**：修正 DNS 或憑證，防止 MITM 攻擊  
- **自簽憑證**：建議使用受信任 CA 簽發  

---

## 10. 排程建議 (Linux Cron 範例)

每天上午 09:00 檢查憑證並寄送郵件：

```bash
0 9 * * * /usr/bin/python3 /root/scripts/ssl_check/check_certs.py --monitor
```

---

## 11. 日誌檔說明

- 日誌同時輸出到檔案與螢幕  
- 日誌級別由 config.json 控制（INFO / WARNING / ERROR）  
- 建議定期清理舊日誌  

---

## 12. 注意事項

1. `hosts.txt` 中主機名必須可被解析，否則檢查會失敗  
2. 建議每週或每天排程檢查，避免憑證過期  
3. Excel 檔案需使用 UTF-8 / openpyxl 開啟  
4. 郵件服務須確保 SMTP 可連線  
5. 資安建議僅供參考，應結合公司安全政策落實
