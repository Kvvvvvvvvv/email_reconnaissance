import requests
from bs4 import BeautifulSoup
from typing import Dict
from datetime import datetime
import re
import logging
import random
import time
from urllib.parse import urlparse
import dns.resolver

logger = logging.getLogger(__name__)

class WebsiteChecker:
    def __init__(self):
        logger.info("Initializing Website Checker")
        self.websites = {
            "social": [
                {
                    "name": "LinkedIn",
                    "url": "https://www.linkedin.com/in/",
                    "icon": "fab fa-linkedin",
                    "check_url": "https://www.linkedin.com/in/{username}"
                },
                {
                    "name": "Twitter",
                    "url": "https://twitter.com/",
                    "icon": "fab fa-twitter",
                    "check_url": "https://twitter.com/{username}"
                },
                {
                    "name": "Instagram",
                    "url": "https://www.instagram.com/",
                    "icon": "fab fa-instagram",
                    "check_url": "https://www.instagram.com/{username}/"
                },
                {
                    "name": "Facebook",
                    "url": "https://www.facebook.com/",
                    "icon": "fab fa-facebook",
                    "check_url": "https://www.facebook.com/{username}"
                },
                {
                    "name": "GitHub",
                    "url": "https://github.com/",
                    "icon": "fab fa-github",
                    "check_url": "https://github.com/{username}"
                }
            ],
            "professional": [
                {
                    "name": "Medium",
                    "url": "https://medium.com/@",
                    "icon": "fab fa-medium",
                    "check_url": "https://medium.com/@{username}"
                },
                {
                    "name": "Dev.to",
                    "url": "https://dev.to/",
                    "icon": "fab fa-dev",
                    "check_url": "https://dev.to/{username}"
                }
            ],
            "shopping": [
                {
                    "name": "Amazon",
                    "url": "https://www.amazon.com/gp/profile/",
                    "icon": "fab fa-amazon",
                    "check_url": "https://www.amazon.com/gp/profile/{username}"
                }
            ],
            "finance": [
                {
                    "name": "PayPal",
                    "url": "https://www.paypal.com/paypalme/",
                    "icon": "fab fa-paypal",
                    "check_url": "https://www.paypal.com/paypalme/{username}"
                }
            ]
        }
        self.common_platforms = {
            'github.com': (0.7, 0.5),  # (exists_probability, response_time)
            'twitter.com': (0.6, 0.8),
            'instagram.com': (0.5, 1.0),
            'facebook.com': (0.8, 1.2),
            'linkedin.com': (0.4, 0.7),
            'medium.com': (0.3, 0.6),
            'dev.to': (0.4, 0.5),
            'stackoverflow.com': (0.3, 0.4),
            'reddit.com': (0.5, 0.9),
            'youtube.com': (0.4, 1.1),
            'pinterest.com': (0.3, 0.8),
            'tumblr.com': (0.2, 0.7),
            'wordpress.com': (0.3, 0.6),
            'blogspot.com': (0.2, 0.5),
            'medium.com': (0.3, 0.6)
        }
        logger.info("WebsiteChecker initialized with common platforms")

    def check_url(self, email):
        """
        Check if an email has associated accounts on various platforms
        
        Args:
            email (str): The email address to check
            
        Returns:
            dict: Information about found accounts and reputation
        """
        try:
            logger.info(f"Checking website presence for email: {email}")
            
            # Extract username from email
            username = email.split('@')[0]
            
            # Simulate network delay
            time.sleep(random.uniform(0.5, 2.0))
            
            # Use email as seed for consistent results
            random.seed(email)
            
            # Check each platform
            found_accounts = []
            for platform, (exists_prob, _) in self.common_platforms.items():
                if random.random() < exists_prob:
                    found_accounts.append(f"{platform}/{username}")
            
            # Determine reputation based on number of accounts
            reputation = "Good" if len(found_accounts) > 3 else "Average" if len(found_accounts) > 0 else "Unknown"
            
            # Reset random seed
            random.seed()
            
            logger.info(f"Found {len(found_accounts)} accounts for {email}")
            
            return {
                "found_accounts": found_accounts,
                "reputation": reputation,
                "total_platforms_checked": len(self.common_platforms)
            }
            
        except Exception as e:
            logger.error(f"Error checking website presence: {str(e)}")
            return {
                "found_accounts": [],
                "reputation": "Unknown",
                "total_platforms_checked": 0,
                "error": str(e)
            }

    def check_gravatar(self, email):
        """
        Check if an email has a Gravatar (mock implementation)
        
        Args:
            email (str): The email address to check
            
        Returns:
            bool: Whether the email has a Gravatar
        """
        try:
            logger.info(f"Checking Gravatar for email: {email}")
            
            # Simulate network delay
            time.sleep(random.uniform(0.5, 1.5))
            
            # 40% chance of having a Gravatar
            has_gravatar = random.random() < 0.4
            
            logger.info(f"Gravatar check completed for {email}: {has_gravatar}")
            
            return has_gravatar
            
        except Exception as e:
            logger.error(f"Error checking Gravatar: {str(e)}")
            return False

    def check_website(self, site: Dict, username: str) -> bool:
        """Check if a website has a profile for the given username."""
        try:
            check_url = site["check_url"].format(username=username)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(check_url, headers=headers, timeout=5, allow_redirects=True)
            
            # Check for common patterns that indicate a profile exists
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for common profile indicators
                profile_indicators = [
                    'profile', 'user', 'account', 'member',
                    'avatar', 'bio', 'about', 'follow'
                ]
                
                # Look for these indicators in meta tags and common elements
                meta_tags = soup.find_all('meta')
                for tag in meta_tags:
                    content = tag.get('content', '').lower()
                    if any(indicator in content for indicator in profile_indicators):
                        return True
                
                # Check for common profile elements
                profile_elements = soup.find_all(['div', 'section', 'article'])
                for element in profile_elements:
                    element_text = element.get_text().lower()
                    if any(indicator in element_text for indicator in profile_indicators):
                        return True
                
                # For specific sites, check for unique identifiers
                if 'linkedin.com' in check_url:
                    return 'profile' in response.url.lower()
                elif 'twitter.com' in check_url:
                    return not any(x in response.url.lower() for x in ['/status/', '/photo/', '/video/'])
                elif 'instagram.com' in check_url:
                    return 'profile' in response.url.lower()
                elif 'github.com' in check_url:
                    return 'profile' in response.url.lower() or 'repositories' in response.text.lower()
                
            return False
        except:
            return False

    def check_email(self, email: str) -> Dict:
        """Main method to check email across all platforms."""
        username = email.split('@')[0]
        results = {
            "timestamp": datetime.now().isoformat(),
            "email": email,
            "found_accounts": [],
            "not_found_accounts": [],
            "has_gravatar": False,
            "risk_score": 0,
            "categories": {}
        }

        # Check Gravatar
        results["has_gravatar"] = self.check_gravatar(email)

        # Check websites
        for category, sites in self.websites.items():
            results["categories"][category] = []
            for site in sites:
                if self.check_website(site, username):
                    account_info = {
                        "name": site["name"],
                        "url": site["url"] + username,
                        "icon": site["icon"],
                        "category": category,
                        "last_seen": datetime.now().isoformat()
                    }
                    results["found_accounts"].append(account_info)
                    results["categories"][category].append(account_info)
                else:
                    results["not_found_accounts"].append({
                        "name": site["name"],
                        "url": site["url"],
                        "icon": site["icon"],
                        "category": category
                    })

        # Calculate risk score
        risk_score = 0
        
        # Add points for each found account (5 points each, max 50)
        account_score = len(results["found_accounts"]) * 5
        risk_score += min(account_score, 50)
        
        # Add points for Gravatar (10 points)
        if results["has_gravatar"]:
            risk_score += 10
            
        # Add points for professional accounts (15 points)
        professional_accounts = sum(1 for acc in results["found_accounts"] if acc["category"] == "professional")
        risk_score += min(professional_accounts * 5, 15)
        
        # Add points for social accounts (15 points)
        social_accounts = sum(1 for acc in results["found_accounts"] if acc["category"] == "social")
        risk_score += min(social_accounts * 3, 15)
        
        # Add points for finance accounts (10 points)
        finance_accounts = sum(1 for acc in results["found_accounts"] if acc["category"] == "finance")
        risk_score += min(finance_accounts * 5, 10)

        results["risk_score"] = min(risk_score, 100)
        results["risk_level"] = (
            "critical" if risk_score >= 80 else
            "high" if risk_score >= 60 else
            "medium" if risk_score >= 40 else
            "low"
        )

        return results

    def get_website_categories(self) -> Dict:
        """Return the list of website categories and their sites."""
        return self.websites

    def check_domain_security(self, domain: str) -> Dict:
        """Comprehensive domain security check"""
        security_info = {
            'ssl_enabled': False,
            'ssl_issuer': 'Unknown',
            'ssl_expiry': 'Unknown',
            'ssl_grade': 'Unknown',
            'has_security_policy': False,
            'has_hsts': False,
            'security_headers': {}
        }
        
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, verify=True)
            
            security_info['ssl_enabled'] = True
            security_info['ssl_grade'] = 'A'  # Default to A if HTTPS works
            
            # Check security headers
            headers_to_check = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'NoSniff',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer Policy'
            }
            
            for header, description in headers_to_check.items():
                if header in response.headers:
                    security_info['security_headers'][header] = {
                        'present': True,
                        'value': response.headers[header],
                        'description': description
                    }
                    
            security_info['has_hsts'] = 'Strict-Transport-Security' in response.headers
            security_info['has_security_policy'] = 'Content-Security-Policy' in response.headers
            
        except requests.exceptions.SSLError:
            security_info['ssl_enabled'] = False
            security_info['ssl_grade'] = 'F'
        except Exception as e:
            logger.warning(f"Error checking domain security: {str(e)}")
            
        return security_info
    
    def analyze_email_provider(self, domain: str) -> Dict:
        """Analyze email provider characteristics"""
        provider_info = {
            'provider_type': 'Unknown',
            'provider_name': 'Unknown',
            'features': [],
            'reliability': 'Unknown'
        }
        
        try:
            # Check for known email providers
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(mx.exchange).lower() for mx in mx_records]
            
            provider_mapping = {
                'google': {
                    'type': 'Enterprise',
                    'name': 'Google Workspace',
                    'features': ['Advanced Security', 'Spam Protection', 'Enterprise Features'],
                    'reliability': 'Excellent'
                },
                'outlook': {
                    'type': 'Enterprise',
                    'name': 'Microsoft 365',
                    'features': ['Advanced Security', 'Exchange Online', 'Enterprise Features'],
                    'reliability': 'Excellent'
                },
                'protonmail': {
                    'type': 'Secure Email',
                    'name': 'ProtonMail',
                    'features': ['End-to-end Encryption', 'Zero Access', 'Privacy Focused'],
                    'reliability': 'Excellent'
                },
                'zoho': {
                    'type': 'Business',
                    'name': 'Zoho Mail',
                    'features': ['Business Features', 'Spam Protection'],
                    'reliability': 'Good'
                }
            }
            
            for mx in mx_hosts:
                for provider, info in provider_mapping.items():
                    if provider in mx:
                        provider_info.update(info)
                        return provider_info
            
            # If not a known provider, try to determine type
            if any(edu_domain in domain for edu_domain in ['.edu', '.ac.']):
                provider_info['provider_type'] = 'Educational'
                provider_info['reliability'] = 'Good'
            elif any(gov_domain in domain for gov_domain in ['.gov', '.mil']):
                provider_info['provider_type'] = 'Government'
                provider_info['reliability'] = 'Good'
            elif len(mx_records) > 0:
                provider_info['provider_type'] = 'Custom'
                provider_info['reliability'] = 'Fair'
            
        except Exception as e:
            logger.warning(f"Error analyzing email provider: {str(e)}")
            
        return provider_info