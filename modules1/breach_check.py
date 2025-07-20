import requests
import json
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
import hashlib
import re
from modules1.threat_assessment import ThreatAssessment

class BreachChecker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.threat_assessor = None
        self.breach_apis = {
            'haveibeenpwned': {
                'url': 'https://haveibeenpwned.com/api/v3/breachedaccount/{}',
                'headers': {
                    'hibp-api-key': 'your-api-key-here',  # You'll need to get an API key
                    'user-agent': 'OSPC-Email-Analyzer'
                },
                'enabled': False  # Set to True if you have API key
            },
            'dehashed': {
                'url': 'https://api.dehashed.com/search?q={}',
                'headers': {
                    'Authorization': 'Bearer your-api-key-here',  # You'll need to get an API key
                    'Accept': 'application/json'
                },
                'enabled': False  # Set to True if you have API key
            }
        }
        
        # Mock breach data for demonstration
        self.mock_breaches = {
            'test@example.com': [
                {
                    'name': 'Adobe Breach 2013',
                    'date': '2013-10-04',
                    'compromised_data': ['email addresses', 'password hints', 'names'],
                    'severity': 'high',
                    'records_count': 153000000
                },
                {
                    'name': 'LinkedIn Breach 2012',
                    'date': '2012-06-22',
                    'compromised_data': ['email addresses', 'passwords'],
                    'severity': 'medium',
                    'records_count': 117000000
                }
            ],
            'admin@gmail.com': [
                {
                    'name': 'Yahoo Breach 2013',
                    'date': '2013-08-01',
                    'compromised_data': ['email addresses', 'passwords', 'names', 'phone numbers'],
                    'severity': 'critical',
                    'records_count': 3000000000
                }
            ]
        }

    def get_threat_assessor(self):
        """Lazy load threat assessor"""
        if self.threat_assessor is None:
            self.threat_assessor = ThreatAssessment()
        return self.threat_assessor

    def check_breaches(self, email: str) -> Dict[str, Any]:
        """Check for breaches across multiple sources"""
        try:
            self.logger.info(f"Checking breaches for: {email}")
            
            results = {
                'email': email,
                'timestamp': datetime.now().isoformat(),
                'breaches': [],
                'breach_count': 0,
                'severity_level': 'none',
                'risk_analysis': {},
                'recommendations': []
            }
            
            # Check real APIs if available
            api_breaches = self._check_breach_apis(email)
            results['breaches'].extend(api_breaches)
            
            # Check mock data for demonstration
            mock_breaches = self._check_mock_breaches(email)
            results['breaches'].extend(mock_breaches)
            
            # Calculate metrics
            results['breach_count'] = len(results['breaches'])
            results['severity_level'] = self._calculate_severity_level(results['breaches'])
            
            # Perform AI-powered risk analysis
            results['risk_analysis'] = self._analyze_breach_risk(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_breach_recommendations(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error checking breaches: {str(e)}")
            return {
                'email': email,
                'error': str(e),
                'breaches': [],
                'breach_count': 0
            }

    def _check_breach_apis(self, email: str) -> List[Dict[str, Any]]:
        """Check breach APIs for real data"""
        breaches = []
        
        for api_name, api_config in self.breach_apis.items():
            if not api_config['enabled']:
                continue
                
            try:
                url = api_config['url'].format(email)
                headers = api_config['headers']
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    breaches.extend(self._parse_api_response(data, api_name))
                    
            except Exception as e:
                self.logger.error(f"Error checking {api_name} API: {str(e)}")
        
        return breaches

    def _check_mock_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check mock breach data for demonstration"""
        return self.mock_breaches.get(email, [])

    def _parse_api_response(self, data: Any, api_name: str) -> List[Dict[str, Any]]:
        """Parse API response into standardized format"""
        breaches = []
        
        if api_name == 'haveibeenpwned':
            for breach in data:
                breaches.append({
                    'name': breach.get('Name', 'Unknown'),
                    'date': breach.get('BreachDate', 'Unknown'),
                    'compromised_data': breach.get('DataClasses', []),
                    'severity': self._determine_severity(breach.get('DataClasses', [])),
                    'records_count': breach.get('PwnCount', 0)
                })
        
        return breaches

    def _determine_severity(self, compromised_data: List[str]) -> str:
        """Determine breach severity based on compromised data types"""
        high_risk_data = ['passwords', 'credit card numbers', 'ssn', 'social security numbers']
        medium_risk_data = ['email addresses', 'names', 'phone numbers', 'addresses']
        
        if any(data.lower() in high_risk_data for data in compromised_data):
            return 'critical'
        elif any(data.lower() in medium_risk_data for data in compromised_data):
            return 'high'
        else:
            return 'medium'

    def _calculate_severity_level(self, breaches: List[Dict[str, Any]]) -> str:
        """Calculate overall severity level"""
        if not breaches:
            return 'none'
        
        severities = [breach.get('severity', 'medium') for breach in breaches]
        
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

    def _analyze_breach_risk(self, breach_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze breach data using AI for risk assessment"""
        try:
            threat_assessor = self.get_threat_assessor()
            
            risk_factors = []
            
            # Analyze breach patterns
            if breach_data['breach_count'] > 5:
                risk_factors.append({
                    'factor': 'Multiple breaches detected',
                    'description': f"Email found in {breach_data['breach_count']} breaches",
                    'severity': 'high',
                    'score': 25
                })
            
            # Analyze breach severity
            if breach_data['severity_level'] == 'critical':
                risk_factors.append({
                    'factor': 'Critical severity breaches',
                    'description': 'Email involved in breaches with highly sensitive data',
                    'severity': 'critical',
                    'score': 40
                })
            
            # Analyze breach recency
            recent_breaches = self._get_recent_breaches(breach_data['breaches'])
            if recent_breaches:
                risk_factors.append({
                    'factor': 'Recent breaches detected',
                    'description': f"Email involved in {len(recent_breaches)} recent breaches",
                    'severity': 'high',
                    'score': 30
                })
            
            # Analyze data types compromised
            sensitive_data_types = self._analyze_compromised_data_types(breach_data['breaches'])
            if sensitive_data_types:
                risk_factors.append({
                    'factor': 'Sensitive data compromised',
                    'description': f"Types of data compromised: {', '.join(sensitive_data_types)}",
                    'severity': 'high',
                    'score': 35
                })
            
            return {
                'risk_factors': risk_factors,
                'overall_risk_score': sum(factor.get('score', 0) for factor in risk_factors),
                'risk_level': self._calculate_risk_level(risk_factors)
            }
            
        except Exception as e:
            self.logger.error(f"Error in breach risk analysis: {str(e)}")
            return {
                'risk_factors': [],
                'overall_risk_score': 0,
                'risk_level': 'unknown',
                'error': str(e)
            }

    def _get_recent_breaches(self, breaches: List[Dict[str, Any]], days: int = 365) -> List[Dict[str, Any]]:
        """Get breaches from the last specified number of days"""
        recent_date = datetime.now() - timedelta(days=days)
        recent_breaches = []
        
        for breach in breaches:
            try:
                breach_date = datetime.strptime(breach['date'], '%Y-%m-%d')
                if breach_date > recent_date:
                    recent_breaches.append(breach)
            except:
                continue
        
        return recent_breaches

    def _analyze_compromised_data_types(self, breaches: List[Dict[str, Any]]) -> List[str]:
        """Analyze what types of data were compromised"""
        all_data_types = []
        
        for breach in breaches:
            data_types = breach.get('compromised_data', [])
            all_data_types.extend(data_types)
        
        # Remove duplicates and return unique data types
        return list(set(all_data_types))

    def _calculate_risk_level(self, risk_factors: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on factors"""
        if not risk_factors:
            return 'low'
        
        total_score = sum(factor.get('score', 0) for factor in risk_factors)
        
        if total_score >= 80:
            return 'critical'
        elif total_score >= 60:
            return 'high'
        elif total_score >= 40:
            return 'medium'
        else:
            return 'low'

    def _generate_breach_recommendations(self, breach_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on breach analysis"""
        recommendations = []
        
        if breach_data['breach_count'] > 0:
            recommendations.append("Change passwords for all accounts using this email address")
            recommendations.append("Enable two-factor authentication where possible")
            recommendations.append("Monitor credit reports for suspicious activity")
            
            if breach_data['severity_level'] in ['high', 'critical']:
                recommendations.append("Consider using a password manager for better security")
                recommendations.append("Review and update security questions for all accounts")
                recommendations.append("Consider freezing credit reports to prevent identity theft")
            
            if breach_data['breach_count'] > 3:
                recommendations.append("Consider using a different email address for sensitive accounts")
                recommendations.append("Set up breach monitoring alerts for this email address")
        
        return recommendations

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Check password strength and if it's been compromised"""
        try:
            # Hash the password for API calls
            password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            
            # Check against HaveIBeenPwned password API
            url = f"https://api.pwnedpasswords.com/range/{password_hash[:5]}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if hash_line.startswith(password_hash[5:]):
                        count = int(hash_line.split(':')[1])
                        return {
                            'is_compromised': True,
                            'appearances': count,
                            'strength': 'weak' if count > 1000 else 'medium'
                        }
            
            return {
                'is_compromised': False,
                'appearances': 0,
                'strength': 'strong'
            }
            
        except Exception as e:
            self.logger.error(f"Error checking password strength: {str(e)}")
            return {
                'is_compromised': False,
                'appearances': 0,
                'strength': 'unknown',
                'error': str(e)
            }