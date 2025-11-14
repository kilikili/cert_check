#!/usr/bin/env python3
import ssl, socket, csv, smtplib, json, traceback, argparse, sys, os
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config.json')
HOST_FILE = os.path.join(SCRIPT_DIR, "hosts.txt")
CSV_FILE = os.path.join(SCRIPT_DIR, "cert_report.csv")

# 設定本地時區（台灣 +08:00）
LOCAL_TZ = timezone(timedelta(hours=8))

def get_host_info():
    """取得執行主機的資訊"""
    hostname = socket.gethostname()
    
    # 取得主機 IP
    try:
        # 嘗試取得對外 IP（透過連接到外部 DNS）
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except:
        # 如果失敗，取得 localhost IP
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "127.0.0.1"
    
    # 取得程式完整路徑
    script_path = os.path.abspath(__file__)
    
    return {
        'hostname': hostname,
        'ip': ip_address,
        'script_path': script_path
    }

def get_cert_expiry(host, port=443, timeout=5, verify=False):
    """取得憑證到期日（UTC）"""

    if verify:
        # 完整驗證模式
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    raise ValueError(f"無法從 {host}:{port} 取得憑證")

                not_after = cert.get('notAfter')
                if not not_after:
                    raise ValueError(f"{host}:{port} 的憑證缺少 notAfter 欄位")

                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                return expiry

    else:
        # 監控模式：不驗證憑證，只取得日期
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            # 使用較寬鬆的 context 避免 WRONG_SIGNATURE_TYPE
            ctx = ssl._create_unverified_context()
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        raise ValueError(f"無法從 {host}:{port} 取得憑證")

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # 新舊版 cryptography 相容
                    if hasattr(cert, "not_valid_after_utc"):
                        expiry = cert.not_valid_after_utc
                    else:
                        expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)

                    return expiry

        except ImportError:
            # Fallback: 用 openssl CLI 解析 PEM
            pem_cert = ssl.get_server_certificate((host, port), timeout=timeout)

            import subprocess
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-noout', '-enddate'],
                    input=pem_cert.encode(),
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    date_str = result.stdout.strip().split('=')[1]
                    expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    return expiry
            except:
                pass

            raise ValueError(f"無法解析 {host}:{port} 的憑證，請安裝 python3-cryptography 套件")

def send_email(subject, body, cfg, attachment_path=None):
    """寄出 email，支援無驗證 SMTP"""
    msg = MIMEMultipart()
    from_addr = cfg.get('smtp_from') or cfg.get('smtp_user') or "cert-monitor"
    msg['From'] = from_addr
    msg['To'] = ", ".join(cfg.get('to', []))
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    # 附上 CSV 報表
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
    parser.add_argument("--monitor", action="store_true", help="監控模式：有即將過期的憑證則回傳 FAIL (exit 2)，否則回傳 SUCCESS (exit 0)，總是寄出郵件")
    args = parser.parse_args()

    cfg_path = Path(CONFIG_FILE)
    if not cfg_path.exists():
        print(f"ERROR: {CONFIG_FILE} not found.")
        return

    cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
    notify_days = cfg.get('notify_before_days', 30)
    verify_ssl = cfg.get('verify_ssl', False)  # 預設不驗證憑證，只取得到期時間

    host_path = Path(HOST_FILE)
    if not host_path.exists():
        print(f"ERROR: {HOST_FILE} not found.")
        return

    hosts = [line.strip() for line in host_path.read_text().splitlines() if line.strip() and not line.strip().startswith('#')]
    rows, alerts = [], []
    now_local = datetime.now(LOCAL_TZ)
    now_utc = datetime.now(timezone.utc)
    check_time = now_local.isoformat()

    for item in hosts:
        if ':' in item:
            host, port = item.split(':', 1)
            try:
                port = int(port)
            except:
                port = 443
        else:
            host, port = item, 443

        try:
            expiry_utc = get_cert_expiry(host, port, verify=verify_ssl)
            expiry_local = expiry_utc.astimezone(LOCAL_TZ)
            days_left = (expiry_utc - now_utc).days
            status = "OK" if days_left > notify_days else "ALERT"
            rows.append([host, port, expiry_local.strftime("%Y-%m-%d %H:%M:%S"), days_left, status, check_time])
            if days_left <= notify_days:
                alerts.append(f"{host}:{port} 憑證將於 {days_left} 天後 ({expiry_local.strftime('%Y-%m-%d %H:%M')}) 到期。")
        except Exception as e:
            rows.append([host, port, "", "", f"ERROR: {e}", check_time])
            alerts.append(f"{host}:{port} 憑證檢查失敗：{e}")
            print(f"DEBUG: failed to check {host}:{port} -> {e}")
            traceback.print_exc()

    # 寫出 CSV 報表
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Expiry (Local Time)", "Days Left", "Status", "Check Time (Local Time)"])
        writer.writerows(rows)

    email_cfg = cfg.get("email", {})
    mail_enabled = email_cfg.get("enabled", False)
    today_str = now_local.strftime("%Y-%m-%d")
    
    # 取得執行主機資訊
    host_info = get_host_info()
    
    # 監控模式：總是發送郵件
    if args.monitor:
        if mail_enabled:
            if alerts:
                subject = f"[SSL 憑證到期監控] FAIL - {today_str} - {len(alerts)} 個警告"
                body = "狀態: FAIL\n\n以下網站 SSL 憑證即將到期或檢查失敗：\n\n" + "\n".join(alerts) + "\n\n"
            else:
                subject = f"[SSL 憑證到期監控] SUCCESS - {today_str} - 全部正常"
                body = f"狀態: SUCCESS\n\n所有網站 SSL 憑證離到期日仍有 {notify_days}天 以上。\n\n"
            body += f"檢查時間：{now_local.strftime('%Y-%m-%d %H:%M:%S %z')}（本地時間）\n"
            body += f"總檢查數：{len(hosts)} 個網站\n"
            body += f"警告數量：{len(alerts)} 個\n"
            body += f"\n執行資訊：\n"
            body += f"  主機名稱：{host_info['hostname']}\n"
            body += f"  主機 IP：{host_info['ip']}\n"
            body += f"  程式路徑：{host_info['script_path']}\n"
            body += f"\n請參閱附件 cert_report.csv 取得完整報表。"
            
            try:
                send_email(subject, body, email_cfg, attachment_path=CSV_FILE)
                print("✅ 已寄出郵件（含 CSV 附件）。")
            except Exception as e:
                print(f"❌ 寄送郵件失敗：{e}")
                traceback.print_exc()
        
        # 輸出監控結果
        if alerts:
            print("=" * 60)
            print("監控結果: FAIL")
            print("=" * 60)
            print(f"發現 {len(alerts)} 個問題：")
            for alert in alerts:
                print(f"  • {alert}")
            print("=" * 60)
            sys.exit(2)  # CRITICAL - 有憑證即將過期
        else:
            print("=" * 60)
            print("監控結果: SUCCESS")
            print("=" * 60)
            print(f"所有 {len(hosts)} 個網站的 SSL 憑證狀態正常")
            print("=" * 60)
            sys.exit(0)  # OK - 全部正常
    
    # 非監控模式：原有邏輯
    elif (alerts or args.force_mail) and mail_enabled:
        subject = f"[SSL 憑證到期報告] {today_str} - {len(alerts)} 個警告" if alerts else f"[SSL 憑證到期報告] {today_str} - 全部正常"
        body = ""
        if alerts:
            body += "以下網站 SSL 憑證即將到期或檢查失敗：\n\n" + "\n".join(alerts) + "\n\n"
        else:
            body += f"所有網站 SSL 憑證離到期日仍有 {notify_days}天 以上。\n\n"
        body += f"檢查時間：{now_local.strftime('%Y-%m-%d %H:%M:%S %z')}（本地時間）\n"
        body += f"\n執行資訊：\n"
        body += f"  主機名稱：{host_info['hostname']}\n"
        body += f"  主機 IP：{host_info['ip']}\n"
        body += f"  程式路徑：{host_info['script_path']}\n"
        body += f"\n請參閱附件 cert_report.csv。"

        try:
            send_email(subject, body, email_cfg, attachment_path=CSV_FILE)
            print("✅ 已寄出郵件（含 CSV 附件）。")
        except Exception as e:
            print(f"❌ 寄送郵件失敗：{e}")
            traceback.print_exc()
    elif alerts:
        print("⚠️ 有憑證即將到期：")
        print("\n".join(alerts))
    else:
        print("✅ 所有憑證狀態正常，未發送郵件。")

if __name__ == "__main__":
    main()

