import dns.resolver
import requests
import socket
import whois
import ssl
import OpenSSL
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class DomainAnalyzer:
    def __init__(self):
        self.known_providers = {
            'google': {
                'name': 'Google Workspace',
                'mx_patterns': ['google.com', 'googlemail.com'],
                'reputation': 'Excellent',
                'features': ['Advanced Security', 'Enterprise Email', 'Anti-phishing']
            },
            'microsoft': {
                'name': 'Microsoft 365',
                'mx_patterns': ['outlook.com', 'microsoft.com', 'protection.outlook.com'],
                'reputation': 'Excellent',
                'features': ['Exchange Online', 'Advanced Threat Protection', 'Enterprise Security']
            },
            'protonmail': {
                'name': 'ProtonMail',
                'mx_patterns': ['protonmail.ch', 'proton.me'],
                'reputation': 'Excellent',
                'features': ['End-to-end Encryption', 'Zero Access', 'Privacy Focused']
            },
            'zoho': {
                'name': 'Zoho Mail',
                'mx_patterns': ['zoho.com', 'zohomail.com'],
                'reputation': 'Good',
                'features': ['Business Email', 'Spam Protection']
            }
        }

    def analyze_domain(self, domain: str) -> Dict:
        """Comprehensive domain analysis (now with DKIM, rDNS, PTR, SSL details, improved scoring, subdomains, blacklist, CAA, SSL trust)"""
        try:
            result = {
                'domain': domain,
                'provider_info': self._analyze_provider(domain),
                'dns_info': self._check_dns(domain),
                'security_info': {},
                'domain_info': self._get_domain_info(domain),
                'timestamp': datetime.now().isoformat(),
                'subdomains': [],
                'blacklist': {},
                'caa_records': []
            }
            # Security info needs DNS info for scoring
            result['security_info'] = self._check_security(domain)
            # Improved security score logic
            score = result['security_info'].get('security_score', 0)
            dns = result['dns_info']
            if dns.get('has_spf'): score += 20
            if dns.get('has_dmarc'): score += 20
            if dns.get('has_dkim'): score += 20
            if result['security_info'].get('ssl_enabled'): score += 20
            if dns.get('has_rdns'): score += 10
            if dns.get('has_ptr'): score += 10
            result['security_info']['score'] = min(score, 100)
            # Add SSL chain trust
            result['security_info']['ssl_chain_trusted'] = self._check_ssl_chain_trust(domain)
            # Add subdomains
            result['subdomains'] = self._enumerate_subdomains(domain)
            # Add blacklist check
            result['blacklist'] = self._check_blacklists(domain, dns.get('a_records', []))
            # Add CAA records
            result['caa_records'] = self._check_caa(domain)
            return result
        except Exception as e:
            logger.error(f"Error in domain analysis for {domain}: {str(e)}")
            return self._get_error_result(domain, str(e))

    def _analyze_provider(self, domain: str) -> Dict:
        """Analyze email provider"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(mx.exchange).lower() for mx in mx_records]

            for provider, info in self.known_providers.items():
                if any(pattern in mx_host for pattern in info['mx_patterns'] for mx_host in mx_hosts):
                    return {
                        'name': info['name'],
                        'type': 'Enterprise',
                        'reputation': info['reputation'],
                        'features': info['features'],
                        'detected': True
                    }

            # Custom provider analysis
            if any('.edu' in mx_host for mx_host in mx_hosts):
                return {
                    'name': 'Educational Institution',
                    'type': 'Education',
                    'reputation': 'Good',
                    'features': ['Institutional Email'],
                    'detected': True
                }
            elif any('.gov' in mx_host for mx_host in mx_hosts):
                return {
                    'name': 'Government Institution',
                    'type': 'Government',
                    'reputation': 'Good',
                    'features': ['Government Email'],
                    'detected': True
                }

            return {
                'name': 'Custom Email Server',
                'type': 'Custom',
                'reputation': 'Unknown',
                'features': ['Custom Configuration'],
                'detected': False
            }

        except Exception as e:
            logger.error(f"Error analyzing provider for {domain}: {str(e)}")
            return {
                'name': 'Unknown',
                'type': 'Unknown',
                'reputation': 'Unknown',
                'features': [],
                'detected': False
            }

    def _check_dns(self, domain: str) -> Dict:
        """Comprehensive DNS checks, now with DKIM, rDNS, PTR"""
        dns_info = {
            'mx_records': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_records': [],
            'a_records': [],
            'ptr_records': [],
            'rdns': [],
            'txt_records': [],
            'has_mx': False,
            'has_spf': False,
            'has_dmarc': False,
            'has_dkim': False,
            'has_ptr': False,
            'has_rdns': False,
            'has_valid_config': False
        }

        try:
            # MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(mx.exchange).rstrip('.') for mx in mx_records]
                dns_info['has_mx'] = True
            except Exception as e:
                logger.warning(f"No MX records for {domain}: {str(e)}")

            # SPF Record
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    record_text = str(record)
                    dns_info['txt_records'].append(record_text)
                    if 'v=spf1' in record_text:
                        dns_info['spf_record'] = record_text
                        dns_info['has_spf'] = True
            except Exception as e:
                logger.warning(f"Error checking SPF for {domain}: {str(e)}")

            # DMARC Record
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    record_text = str(record)
                    if 'v=DMARC1' in record_text:
                        dns_info['dmarc_record'] = record_text
                        dns_info['has_dmarc'] = True
            except Exception as e:
                logger.warning(f"No DMARC record for {domain}: {str(e)}")

            # DKIM Record (look for any TXT at *_domainkey.domain)
            try:
                # Try common selectors
                selectors = ['default', 'google', 'selector1', 'selector2']
                for sel in selectors:
                    dkim_domain = f"{sel}._domainkey.{domain}"
                    try:
                        dkim_txts = dns.resolver.resolve(dkim_domain, 'TXT')
                        for record in dkim_txts:
                            record_text = str(record)
                            if 'v=DKIM1' in record_text:
                                # Parse the DKIM record into structured format
                                parsed_dkim = self._parse_dkim_record(record_text)
                                dns_info['dkim_records'].append({
                                    'selector': sel, 
                                    'record': record_text,
                                    'parsed': parsed_dkim
                                })
                                dns_info['has_dkim'] = True
                    except Exception:
                        continue
            except Exception as e:
                logger.warning(f"Error checking DKIM for {domain}: {str(e)}")

            # A Records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(record) for record in a_records]
            except Exception as e:
                logger.warning(f"No A records for {domain}: {str(e)}")

            # PTR and rDNS for each A record
            for ip in dns_info['a_records']:
                try:
                    # rDNS
                    rdns = socket.gethostbyaddr(ip)[0]
                    dns_info['rdns'].append({'ip': ip, 'rdns': rdns})
                    dns_info['has_rdns'] = True
                except Exception as e:
                    logger.warning(f"No rDNS for {ip}: {str(e)}")
                try:
                    # PTR
                    ptr = dns.resolver.resolve(ip + '.in-addr.arpa', 'PTR')
                    ptr_names = [str(r) for r in ptr]
                    dns_info['ptr_records'].append({'ip': ip, 'ptr': ptr_names})
                    dns_info['has_ptr'] = True
                except Exception as e:
                    logger.warning(f"No PTR for {ip}: {str(e)}")

            dns_info['has_valid_config'] = dns_info['has_mx'] and dns_info['has_spf']

        except Exception as e:
            logger.error(f"Error in DNS checks for {domain}: {str(e)}")

        return dns_info

    def _check_security(self, domain: str) -> Dict:
        """Check domain security, now with SSL cert details"""
        security_info = {
            'ssl_enabled': False,
            'ssl_valid': False,
            'ssl_grade': 'Unknown',
            'security_headers': {},
            'has_security_policy': False,
            'security_score': 0,
            'ssl_issuer': None,
            'ssl_expiry': None,
            'ssl_wildcard': False
        }

        try:
            # Check HTTPS and SSL cert
            try:
                response = requests.get(f"https://{domain}", timeout=10, verify=True)
                security_info['ssl_enabled'] = True
                security_info['ssl_valid'] = True

                # SSL cert details
                try:
                    import ssl, OpenSSL
                    cert = ssl.get_server_certificate((domain, 443))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    issuer = x509.get_issuer()
                    security_info['ssl_issuer'] = str(issuer.commonName) if hasattr(issuer, 'commonName') else str(issuer)
                    security_info['ssl_expiry'] = x509.get_notAfter().decode('utf-8')
                    subject = x509.get_subject()
                    cn = subject.commonName if hasattr(subject, 'commonName') else ''
                    security_info['ssl_wildcard'] = cn.startswith('*.')
                except Exception as e:
                    logger.warning(f"Could not fetch SSL cert details for {domain}: {str(e)}")

                # Check security headers
                headers_to_check = {
                    'Strict-Transport-Security': 'HSTS',
                    'Content-Security-Policy': 'CSP',
                    'X-Frame-Options': 'Frame Protection',
                    'X-Content-Type-Options': 'Content Type Protection',
                    'X-XSS-Protection': 'XSS Protection'
                }

                for header, description in headers_to_check.items():
                    if header in response.headers:
                        security_info['security_headers'][header] = {
                            'value': response.headers[header],
                            'description': description
                        }

                security_info['has_security_policy'] = len(security_info['security_headers']) > 0
                
            except requests.exceptions.SSLError:
                security_info['ssl_grade'] = 'F'
            except Exception as e:
                logger.warning(f"Error checking HTTPS for {domain}: {str(e)}")

            # Calculate security score (new logic)
            score = 0
            if security_info['ssl_enabled']:
                score += 20
            if security_info['ssl_valid']:
                score += 10
            if security_info['has_security_policy']:
                score += 10
            score += len(security_info['security_headers']) * 5
            # Add DNS-based points (to be set by analyze_domain)
            security_info['security_score'] = score

        except Exception as e:
            logger.error(f"Error in security check for {domain}: {str(e)}")

        return security_info

    def _get_domain_info(self, domain: str) -> Dict:
        """Get basic domain information, now with age calculation and registrar info"""
        try:
            domain_info = {
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'last_updated': 'Unknown',
                'status': 'Unknown',
                'age': 'Unknown'
            }

            try:
                w = whois.whois(domain)
                if w.registrar:
                    domain_info['registrar'] = w.registrar
                if w.creation_date:
                    domain_info['creation_date'] = str(w.creation_date)
                    # Calculate age
                    try:
                        if isinstance(w.creation_date, list):
                            creation = w.creation_date[0]
                        else:
                            creation = w.creation_date
                        if isinstance(creation, str):
                            creation = datetime.strptime(creation[:10], '%Y-%m-%d')
                        age_days = (datetime.now() - creation).days
                        if age_days < 30:
                            domain_info['age'] = f"{age_days} days"
                        elif age_days < 365:
                            domain_info['age'] = f"{age_days//30} months"
                        else:
                            domain_info['age'] = f"{age_days//365} years"
                    except Exception as e:
                        domain_info['age'] = 'Unknown'
                if w.expiration_date:
                    domain_info['expiration_date'] = str(w.expiration_date)
                if w.updated_date:
                    domain_info['last_updated'] = str(w.updated_date)
                if w.status:
                    domain_info['status'] = w.status
            except Exception as e:
                logger.warning(f"Error getting WHOIS info for {domain}: {str(e)}")

            return domain_info

        except Exception as e:
            logger.error(f"Error getting domain info for {domain}: {str(e)}")
            return {
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'last_updated': 'Unknown',
                'status': 'Unknown',
                'age': 'Unknown',
                'error': str(e)
            }

    def _calculate_scores(self, result: Dict) -> Dict:
        """Calculate various scores for the domain"""
        scores = {
            'overall_score': 0,
            'security_score': 0,
            'configuration_score': 0,
            'reputation_score': 0
        }

        try:
            # Security Score (40% of total)
            security_score = 0
            if result['security_info']['ssl_enabled']:
                security_score += 20
            if result['security_info']['ssl_valid']:
                security_score += 10
            if result['security_info']['has_security_policy']:
                security_score += 10
            
            # Configuration Score (30% of total)
            config_score = 0
            if result['dns_info']['has_mx']:
                config_score += 10
            if result['dns_info']['has_spf']:
                config_score += 10
            if result['dns_info']['has_dmarc']:
                config_score += 10
            
            # Reputation Score (30% of total)
            reputation_score = 0
            if result['provider_info']['detected']:
                reputation_score += 20
            if result['provider_info']['reputation'] == 'Excellent':
                reputation_score += 10
            elif result['provider_info']['reputation'] == 'Good':
                reputation_score += 5

            # Calculate weighted scores
            scores['security_score'] = security_score
            scores['configuration_score'] = config_score
            scores['reputation_score'] = reputation_score
            
            # Overall score is weighted average
            scores['overall_score'] = (
                (security_score * 0.4) +
                (config_score * 0.3) +
                (reputation_score * 0.3)
            )

        except Exception as e:
            logger.error(f"Error calculating scores: {str(e)}")

        return scores

    def _get_error_result(self, domain: str, error: str) -> Dict:
        """Return a structured error result"""
        return {
            'domain': domain,
            'error': error,
            'provider_info': {
                'name': 'Unknown',
                'type': 'Unknown',
                'reputation': 'Unknown',
                'features': [],
                'detected': False
            },
            'dns_info': {
                'has_mx': False,
                'has_spf': False,
                'has_dmarc': False,
                'mx_records': [],
                'has_valid_config': False
            },
            'security_info': {
                'ssl_enabled': False,
                'ssl_grade': 'Unknown',
                'security_score': 0
            },
            'domain_info': {
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown'
            },
            'scores': {
                'overall_score': 0,
                'security_score': 0,
                'configuration_score': 0,
                'reputation_score': 0
            },
            'timestamp': datetime.now().isoformat()
        }

    def _enumerate_subdomains(self, domain: str) -> list:
        """Enumerate subdomains using crt.sh (no API key needed)"""
        import requests
        subdomains = set()
        try:
            url = f'https://crt.sh/?q=%25.{domain}&output=json'
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data:
                        name = entry.get('name_value')
                        if name:
                            for sub in name.split('\n'):
                                if sub.endswith(domain):
                                    subdomains.add(sub.strip())
                except Exception:
                    # fallback to HTML parse if JSON fails
                    pass
        except Exception as e:
            logger.warning(f"Error enumerating subdomains for {domain}: {str(e)}")
        return sorted(list(subdomains))

    def _check_blacklists(self, domain: str, a_records: list) -> dict:
        """Check domain/IP against public DNSBLs"""
        import dns.resolver
        blacklists = [
            'zen.spamhaus.org',
            'b.barracudacentral.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net'
        ]
        results = {}
        # Check domain
        for bl in blacklists:
            try:
                query = '.'.join(reversed(domain.split('.'))) + '.' + bl
                dns.resolver.resolve(query, 'A')
                results[bl] = True
            except Exception:
                results[bl] = False
        # Check each A record
        for ip in a_records:
            for bl in blacklists:
                try:
                    query = '.'.join(reversed(ip.split('.'))) + '.' + bl
                    dns.resolver.resolve(query, 'A')
                    results[f'{ip}@{bl}'] = True
                except Exception:
                    results[f'{ip}@{bl}'] = False
        return results

    def _check_ssl_chain_trust(self, domain: str) -> bool:
        """Check if SSL certificate chain is trusted"""
        try:
            import ssl
            import OpenSSL
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(ssl.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert_bin = s.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                store = OpenSSL.crypto.X509Store()
                store_ctx = OpenSSL.crypto.X509StoreContext(store, x509)
                store_ctx.verify_certificate()
            return True
        except Exception as e:
            logger.warning(f"SSL chain trust check failed for {domain}: {str(e)}")
            return False

    def _check_caa(self, domain: str) -> list:
        """Check CAA records for the domain"""
        caa_records = []
        try:
            caa = dns.resolver.resolve(domain, 'CAA')
            for record in caa:
                caa_records.append(str(record))
        except Exception as e:
            logger.warning(f"No CAA record for {domain}: {str(e)}")
        return caa_records

    def _parse_dkim_record(self, dkim_record: str) -> Dict:
        """Parse DKIM record into structured format"""
        try:
            # Remove quotes and clean the record
            clean_record = dkim_record.strip('"')
            
            # Parse the DKIM record components
            parts = clean_record.split(';')
            dkim_data = {
                'version': '',
                'key_type': '',
                'public_key': '',
                'notes': '',
                'raw_record': clean_record
            }
            
            for part in parts:
                part = part.strip()
                if part.startswith('v='):
                    dkim_data['version'] = part[2:]
                elif part.startswith('k='):
                    dkim_data['key_type'] = part[2:]
                elif part.startswith('p='):
                    dkim_data['public_key'] = part[2:]
                elif part.startswith('n='):
                    dkim_data['notes'] = part[2:]
                elif part.startswith('s='):
                    dkim_data['service_type'] = part[2:]
                elif part.startswith('t='):
                    dkim_data['flags'] = part[2:]
            
            return dkim_data
        except Exception as e:
            logger.error(f"Error parsing DKIM record: {str(e)}")
            return {
                'version': 'Unknown',
                'key_type': 'Unknown',
                'public_key': 'Error parsing',
                'notes': '',
                'raw_record': dkim_record
            }
