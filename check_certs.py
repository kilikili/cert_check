#!/usr/bin/env python3
import ssl, socket, smtplib, json, traceback, argparse, sys, os
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config.json')
HOST_FILE = os.path.join(SCRIPT_DIR, "hosts.txt")
EXCEL_FILE = os.path.join(SCRIPT_DIR, "cert_report.xlsx")

LOCAL_TZ = timezone(timedelta(hours=8))

# -------------------- Helper Functions --------------------

def get_host_info():
    """取得執行主機資訊"""
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
    return {'hostname': hostname, 'ip': ip_address, 'script_path': os.path.abspath(__file__)}

def get_cert_info(host, port=443, timeout=5):
    """取得憑證資訊並產生安全建議"""
    advice = []
    expiry_utc = None
    tls_version = "N/A"
    sig_algo = "N/A"
    key_size = "N/A"

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        ctx = ssl._create_unverified_context()
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                if hasattr(cert, "not_valid_after_utc"):
                    expiry_utc = cert.not_valid_after_utc
                else:
                    expiry_utc = cert.not_valid_after.replace(tzinfo=timezone.utc)

                sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "N/A"
                key_size = cert.public_key().key_size if hasattr(cert.public_key(), "key_size") else "N/A"

                if sig_algo.lower() in ["sha1", "md5"]:
                    advice.append(f"使用過舊簽章 {sig_algo}，建議更新為 SHA256+RSA/EC。")
                if key_size != "N/A" and key_size < 2048:
                    advice.append(f"公鑰長度 {key_size} 過短，建議 ≥2048。")
                if tls_version in ["SSLv3", "TLSv1", "TLSv1.1"]:
                    advice.append(f"支援舊版 TLS ({tls_version})，建議升級至 TLS1.2/1.3。")

                try:
                    cn_list = [x.value for x in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_list = san_ext.value.get_values_for_type(x509.DNSName)
                    if host not in cn_list + san_list:
                        advice.append("主機名與憑證 CN/SAN 不符，可能造成 MITM 風險。")
                except:
                    pass
                if cert.issuer == cert.subject:
                    advice.append("使用自簽憑證，建議改用受信任 CA 簽發憑證。")
    except Exception as e:
        advice.append(f"憑證檢查失敗：{e}")

    return expiry_utc, tls_version, sig_algo, key_size, "; ".join(advice)

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

# -------------------- 主程式 --------------------

def check_host(host, port, now_utc, notify_days):
    try:
        expiry_utc, tls_version, sig_algo, key_size, advice = get_cert_info(host, port)
        expiry_local = expiry_utc.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S") if expiry_utc else "N/A"
        days_left = (expiry_utc - now_utc).days if expiry_utc else "N/A"
        status = "OK" if expiry_utc and days_left > notify_days else "ALERT"
        if expiry_utc and days_left <= notify_days:
            advice = ("憑證即將到期，請更新；" + advice) if advice else "憑證即將到期，請更新。"
        return [host, port, expiry_local, days_left, status, tls_version, sig_algo, key_size, advice]
    except Exception as e:
        return [host, port, "", "", f"ERROR: {e}", "N/A", "N/A", "N/A", f"檢查失敗：{e}"]

def main():
    parser = argparse.ArgumentParser(description="SSL 憑證到期監控工具 (多執行緒 + Excel)")
    parser.add_argument("--force-mail", action="store_true", help="即使沒有警告也強制寄出郵件")
    parser.add_argument("--monitor", action="store_true", help="監控模式")
    args = parser.parse_args()

    cfg = json.loads(Path(CONFIG_FILE).read_text(encoding='utf-8'))
    notify_days = cfg.get('notify_before_days', 30)
    max_threads = cfg.get('max_threads', 10)

    hosts = [line.strip() for line in Path(HOST_FILE).read_text().splitlines() if line.strip() and not line.startswith("#")]

    now_local = datetime.now(LOCAL_TZ)
    now_utc = datetime.now(timezone.utc)
    rows, alerts = [], []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for item in hosts:
            if ':' in item:
                host, port = item.split(':', 1)
                port = int(port)
            else:
                host, port = item, 443
            futures.append(executor.submit(check_host, host, port, now_utc, notify_days))
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            if row[4] == "ALERT" or row[4].startswith("ERROR"):
                alerts.append(f"{row[0]}:{row[1]} → {row[8]}")

    # 輸出 Excel
    df = pd.DataFrame(rows, columns=["Host","Port","Expiry(Local)","Days Left","Status","TLS Version","Signature","Key Size","Security Advice"])
    df.to_excel(EXCEL_FILE, index=False)

    email_cfg = cfg.get("email", {})
    mail_enabled = email_cfg.get("enabled", False)
    today_str = now_local.strftime("%Y-%m-%d")
    host_info = get_host_info()

    if args.monitor or (alerts and mail_enabled) or args.force_mail:
        subject = f"[SSL 憑證監控] {today_str} - {len(alerts)} 個警告" if alerts else f"[SSL 憑證監控] {today_str} - 全部正常"
        body = "\n".join(alerts) if alerts else "所有網站 SSL 憑證狀態正常。\n"
        body += f"\n檢查時間：{now_local.strftime('%Y-%m-%d %H:%M:%S %z')}\n"
        body += f"主機名稱：{host_info['hostname']}\n主機 IP：{host_info['ip']}\n程式路徑：{host_info['script_path']}\n"
        if mail_enabled:
            try:
                send_email(subject, body, email_cfg, attachment_path=EXCEL_FILE)
                print("✅ 已寄出郵件（含 Excel 附件）。")
            except Exception as e:
                print(f"❌ 寄送郵件失敗：{e}")
                traceback.print_exc()

    if alerts:
        print("="*60)
        print("⚠️ SSL 憑證警告/錯誤")
        for alert in alerts:
            print(f"  • {alert}")
        print("="*60)
        if args.monitor:
            sys.exit(2)
    else:
        print("✅ 所有憑證狀態正常")
        if args.monitor:
            sys.exit(0)

if __name__ == "__main__":
    main()

