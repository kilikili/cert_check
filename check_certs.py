#!/usr/bin/env python3
import ssl, socket, csv, smtplib, json, traceback, argparse, sys, os, subprocess
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

    return {
        'hostname': hostname,
        'ip': ip_address,
        'script_path': script_path
    }


def analyze_cert_security(cert_obj=None, tls_version=None, cipher=None):
    """
    分析憑證安全性（簽章演算法、金鑰長度、TLS 版本、cipher）
    回傳 dict，不會 raise（缺少資訊會以 None/empty 表示）
    """
    security = {
        "tls_version": tls_version,
        "cipher": cipher,  # ssock.cipher() tuple 或 None
        "signature_algorithm": None,
        "key_type": None,
        "key_size": None,
        "security_level": "OK",  # OK or WEAK
        "issues": [],
        "should_renew": False,
    }

    # Cipher check (string)
    try:
        if cipher:
            # cipher can be tuple like ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            if isinstance(cipher, (list, tuple)) and len(cipher) >= 1:
                cname = cipher[0]
            else:
                cname = str(cipher)
            # simple checks for weak ciphers
            if any(x in cname.upper() for x in ("RC4", "DES", "3DES", "NULL", "EXPORT")):
                security["issues"].append(f"不安全的加密套件: {cname}")
    except Exception:
        pass

    # TLS version deprecation
    if tls_version:
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            security["issues"].append(f"已淘汰的 TLS/SSL 版本: {tls_version}")
    # Analyze certificate object if provided (cryptography cert)
    if cert_obj is not None:
        try:
            # signature algorithm
            try:
                sig_algo = cert_obj.signature_hash_algorithm.name if cert_obj.signature_hash_algorithm else None
            except Exception:
                sig_algo = None
            if sig_algo:
                security["signature_algorithm"] = sig_algo
                if sig_algo.lower() in ("sha1", "md5"):
                    security["issues"].append(f"過時的簽章演算法: {sig_algo}")
            # public key
            try:
                pubkey = cert_obj.public_key()
                # lazy import types
                from cryptography.hazmat.primitives.asymmetric import rsa, ec
                if isinstance(pubkey, rsa.RSAPublicKey):
                    key_size = pubkey.key_size
                    security["key_type"] = "RSA"
                    security["key_size"] = key_size
                    if key_size < 2048:
                        security["issues"].append(f"RSA 金鑰長度 {key_size} bits 過短，建議至少 2048")
                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    try:
                        curve_name = pubkey.curve.name
                    except Exception:
                        curve_name = "EC"
                    security["key_type"] = f"EC ({curve_name})"
                    security["key_size"] = None
                else:
                    # unknown pubkey type
                    security["key_type"] = pubkey.__class__.__name__
            except Exception:
                # 無法解析公鑰細節（某些舊版 cryptography 可能行為不同）
                pass
        except Exception:
            pass

    # Decide overall level
    if security["issues"]:
        security["security_level"] = "WEAK"
        security["should_renew"] = True

    return security


def _parse_enddate_with_openssl(pem_text):
    """
    使用 openssl CLI 解析 PEM 並回傳 expiry datetime(UTC) 與部分安全資訊字典（若可）
    """
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-enddate', '-text', '-certopt', 'no_signame'],
            input=pem_text.encode(),
            capture_output=True,
            text=True,
            timeout=6
        )
        if result.returncode == 0 and result.stdout:
            # enddate line: notAfter=Jan 15 12:00:00 2025 GMT
            for line in result.stdout.splitlines():
                if line.strip().startswith("notAfter="):
                    date_str = line.strip().split("=", 1)[1]
                    expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    return expiry, {}
    except Exception:
        pass
    return None, {}


def get_cert_expiry(host, port=443, timeout=5, verify=False):
    """
    取得憑證到期日（UTC）並回傳 (expiry_datetime_utc, security_dict)
    - expiry_datetime_utc: datetime with tzinfo=UTC
    - security_dict: keys: tls_version, cipher, signature_algorithm, key_type, key_size, issues, security_level, should_renew
    """
    # prepare default empty security
    security = {
        "tls_version": None,
        "cipher": None,
        "signature_algorithm": None,
        "key_type": None,
        "key_size": None,
        "security_level": "UNKNOWN",
        "issues": [],
        "should_renew": False,
    }

    # We'll try to obtain: tls_version, cipher, der_cert (binary)
    # use different SSL contexts for verify True/False
    if verify:
        ctx = ssl.create_default_context()
    else:
        # 不驗證模式，用不驗證 context，並嘗試降低 security level 以避免 WRONG_SIGNATURE_TYPE
        try:
            ctx = ssl._create_unverified_context()
            # 嘗試設置較低的 security level，若不支援則忽略
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass
        except Exception:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass

    # connect and fetch binary cert and connection meta
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # TLS version and cipher
                try:
                    tls_ver = ssock.version()  # e.g., "TLSv1.3"
                    cipher = ssock.cipher()    # tuple or None
                    security["tls_version"] = tls_ver
                    security["cipher"] = cipher
                except Exception:
                    tls_ver = None
                    cipher = None

                # try to get DER cert
                try:
                    der = ssock.getpeercert(binary_form=True)
                except Exception:
                    der = None

                # if we got der, try cryptography to parse
                cert_obj = None
                if der:
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_der_x509_certificate(der, default_backend())
                        # get expiry (aware UTC)
                        if hasattr(cert_obj, "not_valid_after_utc"):
                            expiry = cert_obj.not_valid_after_utc
                        else:
                            expiry = cert_obj.not_valid_after.replace(tzinfo=timezone.utc)
                        # analyze
                        sec = analyze_cert_security(cert_obj, tls_ver, cipher)
                        security.update(sec)
                        return expiry, security
                    except Exception:
                        # fallback to PEM parsing if cryptography fails
                        try:
                            pem = ssl.DER_cert_to_PEM_cert(der)
                            expiry, openssl_sec = _parse_enddate_with_openssl(pem)
                            if expiry:
                                security.update(openssl_sec)
                                return expiry, security
                        except Exception:
                            pass

                # If DER not available or parsing failed, try PEM via ssl.get_server_certificate
                try:
                    pem_cert = ssl.get_server_certificate((host, port), timeout=timeout)
                    # parse with openssl CLI
                    expiry, openssl_sec = _parse_enddate_with_openssl(pem_cert)
                    if expiry:
                        security.update(openssl_sec)
                        return expiry, security
                except Exception:
                    pass

                # As last resort, try to use ssock.getpeercert() non-binary
                try:
                    certdict = ssock.getpeercert()
                    if certdict and "notAfter" in certdict:
                        expiry = datetime.strptime(certdict["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        # minimal analyze: set tls/cipher already set
                        sec = analyze_cert_security(None, tls_ver, cipher)
                        security.update(sec)
                        return expiry, security
                except Exception:
                    pass

    except Exception as e:
        # re-raise later with context
        raise

    raise ValueError(f"無法解析 {host}:{port} 的憑證或取得到期日；請確認網路/port/憑證可存取，或安裝 python3-cryptography 與 openssl CLI。")


def send_email(subject, body, cfg, attachment_path=None):
    """寄出 email，支援無驗證 SMTP"""
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
            expiry_utc, security = get_cert_expiry(host, port, verify=verify_ssl)
            expiry_local = expiry_utc.astimezone(LOCAL_TZ)
            days_left = (expiry_utc - now_utc).days
            status = "OK" if days_left > notify_days else "ALERT"

            issues_str = "; ".join(security.get("issues", [])) if security else ""
            cipher_name = ""
            if security and security.get("cipher"):
                try:
                    cipher_name = security["cipher"][0] if isinstance(security["cipher"], (list, tuple)) else str(security["cipher"])
                except Exception:
                    cipher_name = str(security["cipher"])

            rows.append([
                host,
                port,
                expiry_local.strftime("%Y-%m-%d %H:%M:%S"),
                days_left,
                status,
                security.get("tls_version", ""),
                cipher_name,
                security.get("signature_algorithm", ""),
                security.get("key_type", ""),
                security.get("key_size", ""),
                security.get("security_level", ""),
                issues_str,
                check_time
            ])

            if days_left <= notify_days or security.get("security_level") == "WEAK":
                # treat weak certs as alerts too
                alert_msg = f"{host}:{port} 憑證將於 {days_left} 天後 ({expiry_local.strftime('%Y-%m-%d %H:%M')}) 到期。"
                if security.get("security_level") == "WEAK":
                    alert_msg += f" 安全檢查: {security.get('issues')}"
                alerts.append(alert_msg)

        except Exception as e:
            rows.append([host, port, "", "", f"ERROR: {e}", "", "", "", "", "", "", str(e), check_time])
            alerts.append(f"{host}:{port} 憑證檢查失敗：{e}")
            print(f"DEBUG: failed to check {host}:{port} -> {e}")
            traceback.print_exc()

    # 寫出 CSV 報表（擴充欄位）
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Host", "Port", "Expiry (Local Time)", "Days Left", "Status",
            "TLS Version", "Cipher", "Signature Algorithm", "Key Type", "Key Size",
            "Security Level", "Issues", "Check Time (Local Time)"
        ])
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
            sys.exit(2)  # CRITICAL - 有憑證即將過期或弱點
        else:
            print("=" * 60)
            print("監控結果: SUCCESS")
            print("=" * 60)
            print(f"所有 {len(hosts)} 個網站的 SSL 憑證狀態正常")
            print("=" * 60)
            sys.exit(0)  # OK - 全部正常

    # 非監控模式：原有邏輯（但會把 weak 當作 alerts）
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
        print("⚠️ 有憑證即將到期或安全性問題：")
        print("\n".join(alerts))
    else:
        print("✅ 所有憑證狀態正常，未發送郵件。")


if __name__ == "__main__":
    main()

