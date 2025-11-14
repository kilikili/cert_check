#!/usr/bin/env python3
import ssl, socket, csv, smtplib, json, traceback, argparse, sys, os, logging
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config.json')
HOST_FILE = os.path.join(SCRIPT_DIR, "hosts.txt")
EXCEL_FILE = os.path.join(SCRIPT_DIR, "cert_report.xlsx")

# 設定本地時區（台灣 +08:00）
LOCAL_TZ = timezone(timedelta(hours=8))

# 設定 logging
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

def get_host_info():
    """取得執行主機的資訊"""
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except:
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "127.0.0.1"
    script_path = os.path.abspath(__file__)
    return {'hostname': hostname, 'ip': ip_address, 'script_path': script_path}

def get_cert_expiry(host, port=443, timeout=5, verify=False):
    """取得憑證到期日（UTC）"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        raise ImportError("請安裝 python3-cryptography 套件: pip install cryptography")

    # 建立 SSL context
    ctx = ssl._create_unverified_context() if not verify else ssl.create_default_context()
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE

    # 設定低安全等級避免 WRONG_SIGNATURE_TYPE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except:
        pass

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            if not der_cert:
                raise ValueError(f"無法取得 {host}:{port} 憑證")
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            if hasattr(cert, "not_valid_after_utc"):
                expiry = cert.not_valid_after_utc
            else:
                expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
            # 取得 CN/SAN
            try:
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except:
                cn = ""
            san = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except:
                san = []
            return expiry, cn, san

def check_host(host, port, now_utc, notify_days):
    """檢查單一 host 的憑證狀態"""
    try:
        expiry_utc, cn, san = get_cert_expiry(host, port)
        expiry_local = expiry_utc.astimezone(LOCAL_TZ).replace(tzinfo=None)  # 移除 timezone
        days_left = (expiry_utc - now_utc).days
        status = "OK" if days_left > notify_days else "ALERT"

        # 資安建議
        advice = []
        if days_left <= notify_days:
            advice.append("憑證即將到期，請更新")
        if host not in san and host != cn:
            advice.append("主機名與憑證 CN/SAN 不符，可能造成 MITM 風險")
        advice_str = "; ".join(advice) if advice else "正常"

        return [host, port, expiry_local.strftime("%Y-%m-%d %H:%M:%S"), days_left, status, advice_str]
    except Exception as e:
        return [host, port, "", "", f"ERROR: {e}", str(e)]

def send_email(subject, body, cfg, attachment_path=None):
    msg = MIMEMultipart()
    from_addr = cfg.get('smtp_from') or cfg.get('smtp_user') or "cert-monitor"
    msg['From'] = from_addr
    msg['To'] = ", ".join(cfg.get('to', []))
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    if attachment_path and Path(attachment_path).exists():
        with open(attachment_path, "rb") as f:
            part = MIMEApplication(f.read(), Name=Path(attachment_path).name)
        part['Content-Disposition'] = f'attachment; filename="{Path(attachment_path).name}"'
        msg.attach(part)

    server = None
    try:
        server = smtplib.SMTP(cfg.get('smtp_server', 'localhost'), cfg.get('smtp_port', 25), timeout=30)
        server.ehlo()
        if cfg.get('use_starttls'):
            server.starttls()
            server.ehlo()
        if cfg.get('smtp_auth', False):
            server.login(cfg.get('smtp_user', ''), cfg.get('smtp_password', ''))
        server.send_message(msg)
    finally:
        if server:
            try:
                server.quit()
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="SSL 憑證到期監控工具")
    parser.add_argument("--force-mail", action="store_true", help="即使沒有警告也強制寄出郵件")
    parser.add_argument("--monitor", action="store_true", help="監控模式：回傳 FAIL/SUCCESS")
    args = parser.parse_args()

    cfg = json.loads(Path(CONFIG_FILE).read_text(encoding='utf-8'))
    notify_days = cfg.get('notify_before_days', 30)
    max_threads = cfg.get('max_threads', 10)

    hosts = []
    for line in Path(HOST_FILE).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            h, p = line.split(':',1)
            hosts.append((h, int(p)))
        else:
            hosts.append((line, 443))

    logging.info(f"讀取 hosts: {HOST_FILE}")
    now_utc = datetime.now(timezone.utc)
    rows, alerts = [], []

    # 多執行緒 + tqdm
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_host, h, p, now_utc, notify_days): (h, p) for h, p in hosts}
        for future in tqdm(futures, total=len(futures), desc="Progress", ncols=60):
            row = future.result()
            rows.append(row)
            # 即時列印
            if row[4] == "ALERT" or row[4].startswith("ERROR"):
                logging.warning(f"{row[0]}:{row[1]} → {row[5]}")
                alerts.append(f"{row[0]}:{row[1]} → {row[5]}")
            else:
                logging.info(f"{row[0]}:{row[1]} OK")

    # Excel 輸出
    df = pd.DataFrame(rows, columns=["Host","Port","Expiry","Days Left","Status","Security Advice"])
    df.to_excel(EXCEL_FILE, index=False)
    logging.info(f"已寄出郵件（含 Excel 附件）。")

    email_cfg = cfg.get("email", {})
    host_info = get_host_info()
    today_str = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")

    # 發送郵件
    if (alerts or args.force_mail) and email_cfg.get("enabled", False):
        subject = f"[SSL 憑證到期報告] {today_str} - {len(alerts)} 個警告" if alerts else f"[SSL 憑證到期報告] {today_str} - 全部正常"
        body = "\n".join(alerts) if alerts else f"所有網站 SSL 憑證離到期日仍有 {notify_days} 天以上。"
        body += f"\n\n檢查主機: {host_info['hostname']} ({host_info['ip']})\n程式路徑: {host_info['script_path']}"
        try:
            send_email(subject, body, email_cfg, attachment_path=EXCEL_FILE)
            logging.info("✅ 已寄出郵件（含 Excel 附件）。")
        except Exception as e:
            logging.error(f"❌ 寄送郵件失敗：{e}")
            traceback.print_exc()

    # 監控模式 exit code
    if args.monitor:
        if alerts:
            logging.error(f"檢查結果: FAIL ({len(alerts)} 個問題)")
            sys.exit(2)
        else:
            logging.info("檢查結果: SUCCESS")
            sys.exit(0)

if __name__ == "__main__":
    main()

