import whois
import math
import hashlib
import socket
import requests
import ssl
import OpenSSL
from datetime import datetime
from typing import Dict, List, Optional
import logging
from Levenshtein import distance
import re
import json

logger = logging.getLogger(__name__)

class EnhancedDomainAnalyzer:
    def __init__(self):
        self.common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.me']
        self.suspicious_patterns = [
            r'security', r'login', r'signin', r'account', r'update', r'verify',
            r'authenticate', r'wallet', r'payment', r'bank'
        ]
        
    def get_whois_info(self, domain: str) -> Dict:
        """Get detailed WHOIS information for a domain"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            
            domain_age = None
            if creation_date:
                age = datetime.now() - creation_date
                domain_age = age.days
            
            return {
                'registrar': w.registrar,
                'creation_date': creation_date.isoformat() if creation_date else None,
                'expiration_date': expiration_date.isoformat() if expiration_date else None,
                'domain_age_days': domain_age,
                'age_category': self._categorize_domain_age(domain_age),
                'registrant_country': w.country,
                'registrant_org': w.org,
                'last_updated': w.updated_date.isoformat() if w.updated_date else None,
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
                'is_premium': self._check_premium_features(w)
            }
        except Exception as e:
            logger.error(f"Error getting WHOIS info for {domain}: {str(e)}")
            return {
                'error': str(e),
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_age_days': None
            }

    def calculate_entropy(self, email: str) -> Dict:
        """Calculate entropy score for email username to detect randomness"""
        username = email.split('@')[0]
        
        # Calculate Shannon entropy
        prob = [float(username.count(c)) / len(username) for c in dict.fromkeys(list(username))]
        entropy = -sum([p * math.log2(p) for p in prob])
        
        # Analyze character distribution
        char_types = {
            'letters': len([c for c in username if c.isalpha()]),
            'digits': len([c for c in username if c.isdigit()]),
            'special': len([c for c in username if not c.isalnum()])
        }
        
        # Calculate normalized scores
        length_score = min(len(username) / 20, 1.0)  # Normalize by typical max length
        entropy_score = min(entropy / 4, 1.0)  # Normalize by typical max entropy
        
        # Detect patterns
        patterns = {
            'repeating': bool(re.search(r'(.)\1{2,}', username)),
            'sequential': bool(re.search(r'(?:abc|123|xyz)', username.lower())),
            'keyboard_pattern': bool(re.search(r'(?:qwerty|asdf)', username.lower()))
        }
        
        return {
            'entropy': entropy,
            'entropy_score': entropy_score * 100,
            'length_score': length_score * 100,
            'character_distribution': char_types,
            'patterns_detected': patterns,
            'is_likely_random': entropy_score > 0.7 or (char_types['digits'] / len(username)) > 0.4,
            'randomness_confidence': self._calculate_randomness_confidence(entropy_score, char_types, patterns)
        }

    def detect_typosquatting(self, domain: str) -> Dict:
        """Detect potential typosquatting domains"""
        base_domain = domain.split('.')[0]
        results = {
            'similar_domains': [],
            'risk_score': 0,
            'risk_factors': []
        }
        
        # Generate potential typosquatting variations
        variations = self._generate_domain_variations(base_domain)
        
        # Check each variation
        for var in variations:
            for tld in self.common_tlds:
                variant = f"{var}{tld}"
                try:
                    ip = socket.gethostbyname(variant)
                    distance_score = distance(domain, variant)
                    if distance_score <= 2:  # Close enough to be suspicious
                        results['similar_domains'].append({
                            'domain': variant,
                            'ip': ip,
                            'distance_score': distance_score,
                            'suspicious_patterns': self._check_suspicious_patterns(variant)
                        })
                except socket.gaierror:
                    continue
        
        # Calculate risk score based on findings
        results['risk_score'] = self._calculate_typosquatting_risk(results['similar_domains'])
        results['risk_factors'] = self._identify_risk_factors(results['similar_domains'])
        
        return results

    def check_gravatar(self, email: str) -> Dict:
        """Check Gravatar profile information"""
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{email_hash}.json"
        
        try:
            response = requests.get(gravatar_url)
            if response.status_code == 200:
                profile_data = response.json()
                return {
                    'exists': True,
                    'profile_url': f"https://www.gravatar.com/{email_hash}",
                    'avatar_url': f"https://www.gravatar.com/avatar/{email_hash}",
                    'profile_data': self._extract_gravatar_data(profile_data)
                }
            return {
                'exists': False,
                'profile_url': None,
                'avatar_url': None,
                'profile_data': None
            }
        except Exception as e:
            logger.error(f"Error checking Gravatar for {email}: {str(e)}")
            return {'error': str(e), 'exists': False}

    def analyze_ssl_chain(self, domain: str) -> Dict:
        """Perform detailed SSL certificate chain analysis"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    chain = []
                    while x509:
                        chain.append({
                            'subject': dict(x509.get_subject().get_components()),
                            'issuer': dict(x509.get_issuer().get_components()),
                            'version': x509.get_version(),
                            'serial_number': x509.get_serial_number(),
                            'not_before': x509.get_notBefore().decode(),
                            'not_after': x509.get_notAfter().decode(),
                            'has_expired': x509.has_expired(),
                            'signature_algorithm': x509.get_signature_algorithm().decode(),
                            'extensions': self._get_cert_extensions(x509)
                        })
                        # Try to get the next certificate in chain
                        try:
                            x509 = OpenSSL.crypto.load_certificate(
                                OpenSSL.crypto.FILETYPE_ASN1,
                                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509)
                            )
                        except Exception:
                            break
                    
                    return {
                        'chain_length': len(chain),
                        'chain': chain,
                        'is_valid': not any(cert['has_expired'] for cert in chain),
                        'trust_score': self._calculate_ssl_trust_score(chain),
                        'recommendations': self._get_ssl_recommendations(chain)
                    }
        except Exception as e:
            logger.error(f"Error analyzing SSL chain for {domain}: {str(e)}")
            return {'error': str(e), 'is_valid': False}

    def _categorize_domain_age(self, age_days: Optional[int]) -> str:
        """Categorize domain age"""
        if not age_days:
            return 'Unknown'
        if age_days < 30:
            return 'Very New'
        if age_days < 180:
            return 'New'
        if age_days < 365:
            return 'Recent'
        if age_days < 730:
            return 'Established'
        return 'Mature'

    def _check_premium_features(self, whois_data) -> bool:
        """Check if domain has premium features"""
        if not whois_data:
            return False
        premium_indicators = ['premium', 'private', 'protected']
        status = whois_data.status
        if isinstance(status, list):
            return any(any(ind in str(s).lower() for ind in premium_indicators) for s in status)
        return any(ind in str(status).lower() for ind in premium_indicators)

    def _generate_domain_variations(self, domain: str) -> List[str]:
        """Generate possible typosquatting variations"""
        variations = set()
        
        # Character substitution
        for i in range(len(domain)):
            # Adjacent key substitutions
            variations.add(domain[:i] + domain[i+1:])  # Deletion
            if i < len(domain) - 1:
                variations.add(domain[:i] + domain[i+1] + domain[i] + domain[i+2:])  # Transposition
            
        # Common substitutions
        substitutions = {
            'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 
            's': ['5', '$'], 't': ['7'], 'b': ['8'], 'g': ['9']
        }
        for i, char in enumerate(domain):
            if char.lower() in substitutions:
                for sub in substitutions[char.lower()]:
                    variations.add(domain[:i] + sub + domain[i+1:])
        
        return list(variations)

    def _check_suspicious_patterns(self, domain: str) -> List[str]:
        """Check domain for suspicious patterns"""
        found_patterns = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                found_patterns.append(pattern)
        return found_patterns

    def _calculate_typosquatting_risk(self, similar_domains: List[Dict]) -> float:
        """Calculate risk score for typosquatting"""
        if not similar_domains:
            return 0
            
        total_score = 0
        for domain in similar_domains:
            # Base score from edit distance (closer = higher risk)
            distance_score = (3 - domain['distance_score']) * 20 if domain['distance_score'] <= 2 else 0
            
            # Additional points for suspicious patterns
            pattern_score = len(domain.get('suspicious_patterns', [])) * 10
            
            total_score += distance_score + pattern_score
            
        # Normalize to 0-100
        return min(total_score / len(similar_domains), 100)

    def _identify_risk_factors(self, similar_domains: List[Dict]) -> List[Dict]:
        """Identify specific risk factors from similar domains"""
        risk_factors = []
        
        for domain in similar_domains:
            if domain['distance_score'] == 1:
                risk_factors.append({
                    'type': 'High Similarity',
                    'description': f"Very similar domain found: {domain['domain']}",
                    'severity': 'High'
                })
            if domain.get('suspicious_patterns'):
                risk_factors.append({
                    'type': 'Suspicious Patterns',
                    'description': f"Suspicious patterns in domain {domain['domain']}: {', '.join(domain['suspicious_patterns'])}",
                    'severity': 'Medium'
                })
                
        return risk_factors

    def _extract_gravatar_data(self, profile_data: Dict) -> Dict:
        """Extract relevant information from Gravatar profile"""
        try:
            entry = profile_data.get('entry', [{}])[0]
            return {
                'display_name': entry.get('displayName'),
                'urls': entry.get('urls', []),
                'photos': entry.get('photos', []),
                'accounts': entry.get('accounts', []),
                'last_updated': entry.get('lastUpdated')
            }
        except Exception:
            return {}

    def _get_cert_extensions(self, cert) -> Dict:
        """Extract certificate extensions"""
        extensions = {}
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            extensions[ext.get_short_name().decode()] = str(ext)
        return extensions

    def _calculate_ssl_trust_score(self, chain: List[Dict]) -> int:
        """Calculate trust score for SSL chain"""
        score = 100
        
        # Check chain length
        if len(chain) < 2:
            score -= 30
        
        # Check expiration
        if any(cert['has_expired'] for cert in chain):
            score -= 50
        
        # Check algorithms
        for cert in chain:
            if 'sha1' in cert['signature_algorithm'].lower():
                score -= 20
                break
        
        # Check validity period
        try:
            end_date = datetime.strptime(chain[0]['not_after'], '%Y%m%d%H%M%SZ')
            days_until_expiry = (end_date - datetime.now()).days
            if days_until_expiry < 30:
                score -= 20
        except Exception:
            score -= 10
            
        return max(score, 0)

    def _get_ssl_recommendations(self, chain: List[Dict]) -> List[str]:
        """Generate SSL configuration recommendations"""
        recommendations = []
        
        if len(chain) < 2:
            recommendations.append("Incomplete certificate chain detected. Install intermediate certificates.")
            
        if any(cert['has_expired'] for cert in chain):
            recommendations.append("Certificate has expired. Renew SSL certificate immediately.")
            
        if any('sha1' in cert['signature_algorithm'].lower() for cert in chain):
            recommendations.append("Weak signature algorithm (SHA1) detected. Upgrade to SHA256 or better.")
            
        try:
            end_date = datetime.strptime(chain[0]['not_after'], '%Y%m%d%H%M%SZ')
            days_until_expiry = (end_date - datetime.now()).days
            if days_until_expiry < 30:
                recommendations.append(f"Certificate expires in {days_until_expiry} days. Plan renewal soon.")
        except Exception:
            pass
            
        return recommendations

    def _calculate_randomness_confidence(self, entropy_score: float, char_types: Dict, patterns: Dict) -> float:
        """Calculate confidence score for randomness detection"""
        confidence = entropy_score * 50  # Base confidence from entropy
        
        # Adjust based on character distribution
        total_chars = sum(char_types.values())
        if total_chars > 0:
            digit_ratio = char_types['digits'] / total_chars
            special_ratio = char_types['special'] / total_chars
            
            if digit_ratio > 0.3:
                confidence += 20
            if special_ratio > 0.1:
                confidence += 15
                
        # Reduce confidence if patterns detected
        if patterns['repeating']:
            confidence -= 20
        if patterns['sequential']:
            confidence -= 15
        if patterns['keyboard_pattern']:
            confidence -= 10
            
        return max(min(confidence, 100), 0)  # Ensure between 0 and 100 