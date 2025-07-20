import dns.resolver
import socket
import requests
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from modules1.email_verification_services import EmailVerificationServices

class EnhancedEmailValidator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.email_verifier = EmailVerificationServices()
        
    def validate_email_format(self, email):
        """Validate email format using advanced regex pattern"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def check_disposable_email(self, domain):
        """Check if the email domain is from a disposable email service"""
        disposable_domains = [
            'tempmail.com', 'throwawaymail.com', '10minutemail.com',
            'guerrillamail.com', 'mailinator.com', 'yopmail.com'
            # Add more disposable email domains as needed
        ]
        return any(domain.lower().endswith(d) for d in disposable_domains)

    def verify_dns_records(self, domain):
        """Verify DNS records including MX, A, and SPF records"""
        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            
            # Check A records
            a_records = dns.resolver.resolve(domain, 'A')
            
            # Check SPF records
            try:
                spf_records = dns.resolver.resolve(domain, 'TXT')
                has_spf = any('v=spf1' in str(record) for record in spf_records)
            except:
                has_spf = False

            return {
                'has_mx': bool(mx_records),
                'has_a': bool(a_records),
                'has_spf': has_spf
            }
        except Exception as e:
            self.logger.error(f"DNS verification error for {domain}: {str(e)}")
            return {
                'has_mx': False,
                'has_a': False,
                'has_spf': False
            }

    def check_smtp_connection(self, domain):
        """Test SMTP connection to verify mail server"""
        try:
            smtp_server = str(dns.resolver.resolve(domain, 'MX')[0].exchange)
            socket.create_connection((smtp_server, 25), timeout=10)
            return True
        except Exception as e:
            self.logger.error(f"SMTP connection error for {domain}: {str(e)}")
            return False

    def check_reputation(self, email):
        """Check email reputation using various indicators"""
        domain = email.split('@')[1]
        reputation_score = 100
        
        # Check DNS records
        dns_results = self.verify_dns_records(domain)
        if not dns_results['has_mx']:
            reputation_score -= 30
        if not dns_results['has_spf']:
            reputation_score -= 10
            
        # Check if disposable
        if self.check_disposable_email(domain):
            reputation_score -= 50
            
        # Check SMTP connection
        if not self.check_smtp_connection(domain):
            reputation_score -= 20
            
        return max(0, reputation_score)

    async def validate_email(self, email):
        """Comprehensive email validation"""
        try:
            results = {
                'email': email,
                'is_valid_format': False,
                'domain_exists': False,
                'is_disposable': False,
                'reputation_score': 0,
                'verification_results': {},
                'dns_checks': {},
                'smtp_check': False
            }

            # Basic format check
            results['is_valid_format'] = self.validate_email_format(email)
            if not results['is_valid_format']:
                return results

            domain = email.split('@')[1]
            
            # Run checks in parallel
            with ThreadPoolExecutor(max_workers=3) as executor:
                dns_future = executor.submit(self.verify_dns_records, domain)
                smtp_future = executor.submit(self.check_smtp_connection, domain)
                disposable_future = executor.submit(self.check_disposable_email, domain)
                
                results['dns_checks'] = dns_future.result()
                results['smtp_check'] = smtp_future.result()
                results['is_disposable'] = disposable_future.result()

            # Additional verifications using existing service
            results['verification_results'] = await self.email_verifier.verify_email(email)
            
            # Calculate reputation score
            results['reputation_score'] = self.check_reputation(email)
            
            # Determine if domain exists based on DNS checks
            results['domain_exists'] = results['dns_checks']['has_mx'] or results['dns_checks']['has_a']

            return results

        except Exception as e:
            self.logger.error(f"Error validating email {email}: {str(e)}")
            return None
