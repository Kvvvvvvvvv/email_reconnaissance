import dns.resolver
import smtplib

def get_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange)
    except:
        return None

def smtp_check(email):
    domain = email.split('@')[1]
    mx = get_mx_record(domain)
    if not mx:
        return False
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx)
        server.helo()
        server.mail("test@example.com")
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250
    except:
        return False