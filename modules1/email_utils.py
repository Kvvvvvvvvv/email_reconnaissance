import re
import smtplib
import dns.resolver
from modules1.breach_check import BreachChecker
from modules1.scraper import scrape_emails
from modules1.osint_mock import find_osint_sources
from modules1.website_checker import WebsiteChecker
from modules1.email_verification_services import EmailVerificationServices
from datetime import datetime

class EmailUtils:
    @staticmethod
    def validate_email(email):
        """Validate email format using a comprehensive regex pattern."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def smtp_check(email):
        """Check if email domain has valid MX records and can receive mail."""
        try:
            domain = email.split('@')[1]
            mx = dns.resolver.resolve(domain, 'MX')[0].exchange.to_text()
            server = smtplib.SMTP(mx, timeout=10)
            server.helo()
            server.mail('probe@example.com')
            code, _ = server.rcpt(email)
            server.quit()
            return code == 250
        except:
            return False

    @staticmethod
    def analyze_email(email):
        """Comprehensive email analysis."""
        website_checker = WebsiteChecker()
        verification_services = EmailVerificationServices()
        
        # Basic validation
        if not EmailUtils.validate_email(email):
            return {
                "email": email,
                "valid": False,
                "error": "Invalid email format"
            }
        
        # Get OSINT results
        osint_results = find_osint_sources(email)
        
        # Get verification service results
        verification_results = verification_services.analyze_email(email)
        
        # Perform all checks
        result = {
            "email": email,
            "valid": True,
            "timestamp": datetime.now().isoformat(),
            "smtp": EmailUtils.smtp_check(email),
            "breaches": BreachChecker.check_breaches(email),
            "scraped": scrape_emails(email.split('@')[1]),
            "osint_dbs": osint_results["sources_checked"],
            "website_presence": website_checker.check_email(email),
            "verification_services": verification_results,
            "risk_score": 0
        }
        
        # Merge OSINT results into website presence
        result["website_presence"].update({
            "reputation": osint_results["reputation"],
            "social_profiles": osint_results["social_profiles"],
            "paste_sites": osint_results["paste_sites"]
        })
        
        # Calculate risk score based on findings
        risk_score = 0
        
        # Add points for each breach found
        risk_score += len(result["breaches"]) * 10
        
        # Add points for each OSINT database match
        risk_score += len(result["osint_dbs"]) * 5
        
        # Add points for each website presence
        risk_score += len(result["website_presence"].get("found_accounts", [])) * 2
        
        # Add points for SMTP validation
        if result["smtp"]:
            risk_score += 5
            
        # Add points from OSINT risk score
        risk_score += osint_results["risk_score"] // 2
        
        # Add points from verification services
        risk_score += verification_results["risk_score"] // 2
        
        # Cap the risk score at 100
        result["risk_score"] = min(risk_score, 100)
        
        return result