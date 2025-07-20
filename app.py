from flask import Flask, render_template, request, jsonify, send_file
import logging
import socket
import re
import json
import traceback
from datetime import datetime
from modules1.osint_mock import OSINTScanner
from modules1.website_checker import WebsiteChecker
from modules1.email_verification_services import EmailVerificationServices
from modules1.email_utils import EmailUtils
from modules1.breach_check import BreachChecker
from modules1.news_feed import NewsFeed
from modules1.advanced_scraper import AdvancedEmailScraper
from modules1.enhanced_validator import EnhancedEmailValidator
from modules1.threat_assessment import ThreatAssessment
from modules1.domain_analyzer import DomainAnalyzer
from modules1.enhanced_domain_analyzer import EnhancedDomainAnalyzer
import dns.resolver  # Importing dns.resolver for DNS queries
import matplotlib.pyplot as plt
import io
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize modules
try:
    osint_scanner = OSINTScanner()
    website_checker = WebsiteChecker()
    email_verifier = EmailVerificationServices()
    breach_checker = BreachChecker()
    news_feed = NewsFeed()
    advanced_scraper = AdvancedEmailScraper()
    enhanced_validator = EnhancedEmailValidator()
    threat_assessor = ThreatAssessment()
    domain_analyzer = DomainAnalyzer()  # Initialize DomainAnalyzer
    enhanced_analyzer = EnhancedDomainAnalyzer()
    logger.info("All modules initialized successfully")
except Exception as e:
    logger.error(f"Error initializing modules: {str(e)}")
    raise

# Common social media platforms to check
SOCIAL_PLATFORMS = {
    'github': 'https://github.com/{}',
    'twitter': 'https://twitter.com/{}',
    'instagram': 'https://instagram.com/{}',
    'facebook': 'https://facebook.com/{}',
    'linkedin': 'https://linkedin.com/in/{}',
    'reddit': 'https://reddit.com/user/{}',
    'medium': 'https://medium.com/@{}',
    'dev.to': 'https://dev.to/{}',
    'hackerrank': 'https://hackerrank.com/{}',
    'leetcode': 'https://leetcode.com/{}',
    'codechef': 'https://codechef.com/users/{}',
    'codeforces': 'https://codeforces.com/profile/{}',
    'stackoverflow': 'https://stackoverflow.com/users/{}',
    'quora': 'https://quora.com/profile/{}',
    'pinterest': 'https://pinterest.com/{}',
    'tiktok': 'https://tiktok.com/@{}',
    'youtube': 'https://youtube.com/@{}',
    'twitch': 'https://twitch.tv/{}',
    'spotify': 'https://open.spotify.com/user/{}',
    'soundcloud': 'https://soundcloud.com/{}',
    'behance': 'https://behance.net/{}',
    'dribbble': 'https://dribbble.com/{}',
    'deviantart': 'https://deviantart.com/{}',
    'flickr': 'https://flickr.com/photos/{}',
    '500px': 'https://500px.com/{}',
    'vimeo': 'https://vimeo.com/{}',
    'gitlab': 'https://gitlab.com/{}',
    'bitbucket': 'https://bitbucket.org/{}',
    'steam': 'https://steamcommunity.com/id/{}',
    'discord': 'https://discord.com/users/{}'
}

def check_username(username):
    """Check username availability across platforms"""
    results = {
        'username': username,
        'timestamp': datetime.now().isoformat(),
        'platforms': {}
    }
    
    for platform, url_template in SOCIAL_PLATFORMS.items():
        try:
            url = url_template.format(username)
            exists = website_checker.check_url(url)
            results['platforms'][platform] = {
                'url': url,
                'exists': exists,
                'status': 'Found' if exists else 'Not Found'
            }
        except Exception as e:
            logger.error(f"Error checking {platform}: {str(e)}")
            results['platforms'][platform] = {
                'url': url,
                'exists': False,
                'status': 'Error',
                'error': str(e)
            }
    
    return results

def get_username_analysis(username):
    """Get comprehensive username analysis"""
    try:
        logger.info(f"Starting username analysis for: {username}")
        
        # Basic validation
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        # Check username across platforms
        platform_results = check_username(username)
        
        # Get breach information
        breach_info = breach_checker.check_breaches(username)
        
        # Get OSINT information
        osint_info = osint_scanner.scan_username(username)
        
        # Calculate presence score
        total_platforms = len(SOCIAL_PLATFORMS)
        found_platforms = sum(1 for p in platform_results['platforms'].values() if p['exists'])
        presence_score = (found_platforms / total_platforms) * 100
        
        # Determine presence level
        if presence_score >= 70:
            presence_level = 'high'
        elif presence_score >= 30:
            presence_level = 'medium'
        else:
            presence_level = 'low'
        
        result = {
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'platform_results': platform_results,
            'breach_info': breach_info,
            'osint_info': osint_info,
            'presence_metrics': {
                'score': presence_score,
                'level': presence_level,
                'total_platforms': total_platforms,
                'found_platforms': found_platforms
            }
        }
        logger.info(f"Username analysis result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error during username analysis: {str(e)}\n{traceback.format_exc()}")
        raise

@app.route('/', methods=['GET', 'POST'])
def index():
    """Handle the main page and email analysis."""
    email_info = None
    error_message = None
    
    # Try to get news items, default to empty list if failed
    try:
        news_items = news_feed.fetch_news()
    except Exception as e:
        logger.error(f"Error fetching news: {str(e)}")
        news_items = []

    # Handle POST request (email analysis)
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            error_message = "Please enter an email address"
        else:
            try:
                # Get email analysis
                email_info = get_email_analysis(email)
                logger.info(f"Email analysis completed for: {email}")
            except Exception as e:
                logger.error(f"Error analyzing email: {str(e)}")
                error_message = str(e)    # Render the template with all our data
    return render_template('index.html',
                        app_name="OSPC Email Analyzer",
                        app_version="1.0.0",
                        now=datetime.now(),
                        email_info=email_info,
                        error_message=error_message,
                        news_items=news_items)

def is_valid_email(email):
    """Check if the email format is valid"""
    return enhanced_validator.validate_email_format(email)

def analyze_domain(domain):
    """Analyze domain characteristics using the new DomainAnalyzer"""
    try:
        # Use the new domain analyzer for comprehensive analysis
        result = domain_analyzer.analyze_domain(domain)
        logger.info(f"Domain analysis completed successfully for {domain}")
        return result
    except Exception as e:
        logger.error(f"Error in domain analysis: {str(e)}")
        return domain_analyzer._get_error_result(domain, str(e))
    try:
        logger.info(f"Starting comprehensive domain analysis for: {domain}")
        
        # Get domain security info
        security_info = website_checker.check_domain_security(domain)
        
        # Get email provider info
        provider_info = website_checker.analyze_email_provider(domain)
        
        # Initialize results with provider info
        domain_info = {
            'domain': domain,
            'domain_info': {
                'type': provider_info['provider_type'],
                'provider': provider_info['provider_name'],
                'features': provider_info['features'],
                'reliability': provider_info['reliability'],
                'last_updated': datetime.now().isoformat()
            },
            'security_info': security_info,
            'dns_info': {
                'has_mx': False,
                'has_spf': False,
                'has_dmarc': False,
                'mx_records': [],
                'spf_record': '',
                'dmarc_record': ''
            }
        }

        # Perform DNS checks
        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            domain_info['dns_info']['has_mx'] = True
            domain_info['dns_info']['mx_records'] = [str(mx.exchange).rstrip('.') for mx in mx_records]
            
            # Check SPF record
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    record_text = str(record)
                    if 'v=spf1' in record_text:
                        domain_info['dns_info']['has_spf'] = True
                        domain_info['dns_info']['spf_record'] = record_text
                        break
            except Exception:
                logger.warning(f"No SPF record found for {domain}")
            
            # Check DMARC record
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    record_text = str(record)
                    if 'v=DMARC1' in record_text:
                        domain_info['dns_info']['has_dmarc'] = True
                        domain_info['dns_info']['dmarc_record'] = record_text
                        break
            except Exception:
                logger.warning(f"No DMARC record found for {domain}")
                
        except Exception as e:
            logger.warning(f"Error checking DNS records: {str(e)}")
        
        # Calculate overall security score
        security_score = 0
        if domain_info['dns_info']['has_mx']:
            security_score += 20
        if domain_info['dns_info']['has_spf']:
            security_score += 20
        if domain_info['dns_info']['has_dmarc']:
            security_score += 20
        if security_info['ssl_enabled']:
            security_score += 20
        if security_info['has_security_policy']:
            security_score += 20
            
        # Add security score and rating
        domain_info['security_info']['score'] = security_score
        if security_score >= 80:
            domain_info['security_info']['rating'] = 'Excellent'
        elif security_score >= 60:
            domain_info['security_info']['rating'] = 'Good'
        elif security_score >= 40:
            domain_info['security_info']['rating'] = 'Fair'
        else:
            domain_info['security_info']['rating'] = 'Poor'
            
        logger.info(f"Domain analysis completed for {domain} with security score {security_score}")
        return domain_info
        
    except Exception as e:
        logger.error(f"Error in domain analysis: {str(e)}")
        return {
            'domain': domain,
            'error': str(e),
            'domain_info': {
                'type': 'Unknown',
                'provider': 'Unknown',
                'features': [],
                'reliability': 'Unknown'
            },
            'security_info': {
                'ssl_enabled': False,
                'rating': 'Unknown'
            },
            'dns_info': {
                'has_mx': False,
                'has_spf': False,
                'has_dmarc': False
            }
        }

def analyze_email_pattern(email):
    """Analyze the pattern of an email address"""
    try:
        logger.info(f"Analyzing email pattern: {email}")
        
        # Split email into username and domain
        username, domain = email.split('@')
        
        # Initialize pattern analysis
        pattern = {
            'score': 0,
            'type': 'standard',
            'has_special_chars': False,
            'is_random': False,
            'length': len(username)
        }
        
        # Check for special characters
        special_chars = set('.-_+')
        if any(char in special_chars for char in username):
            pattern['has_special_chars'] = True
            pattern['score'] += 20
        
        # Check for numbers
        if any(char.isdigit() for char in username):
            pattern['score'] += 10
        
        # Check for potential random strings
        if len(username) >= 12 and any(char.isdigit() for char in username):
            pattern['is_random'] = True
            pattern['score'] += 30
            pattern['type'] = 'random'
        elif len(username) < 6:
            pattern['type'] = 'short'
        elif username.isalpha():
            pattern['type'] = 'name-based'
        elif username.isalnum():
            pattern['type'] = 'alphanumeric'
        
        # Cap the score at 100
        pattern['score'] = min(pattern['score'], 100)
        
        logger.info(f"Email pattern analysis completed with score: {pattern['score']}")
        return pattern
        
    except Exception as e:
        logger.error(f"Error in email pattern analysis: {str(e)}")
        return None

def get_email_analysis(email):
    """Get comprehensive email analysis with enhanced features"""
    try:
        logger.info(f"Starting enhanced email analysis for: {email}")
        
        # Validate email format
        if not is_valid_email(email):
            logger.warning(f"Invalid email format: {email}")
            raise ValueError("Invalid email format. Please enter a valid email address.")
            
        # Get domain from email
        domain = email.split('@')[1]
        
        # Initialize analyzers
        domain_analyzer = DomainAnalyzer()
        enhanced_analyzer = EnhancedDomainAnalyzer()
        
        # Get basic domain analysis
        domain_analysis = domain_analyzer.analyze_domain(domain) or {}
        logger.info(f"Basic domain analysis completed for {domain}")
        
        # Get enhanced domain analysis
        whois_info = enhanced_analyzer.get_whois_info(domain)
        entropy_analysis = enhanced_analyzer.calculate_entropy(email)
        typosquatting_analysis = enhanced_analyzer.detect_typosquatting(domain)
        ssl_chain_analysis = enhanced_analyzer.analyze_ssl_chain(domain)
        gravatar_info = enhanced_analyzer.check_gravatar(email)
        
        # Merge all analysis results
        result = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'domain_analysis': {
                **domain_analysis,
                'whois_info': whois_info,
                'ssl_chain_analysis': ssl_chain_analysis,
                'typosquatting_analysis': typosquatting_analysis
            },
            'email_analysis': {
                'entropy_analysis': entropy_analysis,
                'gravatar_info': gravatar_info
            }
        }
        
        # Get breach information
        try:
            breach_info = breach_checker.check_breaches(email) or {}
            result['breach_info'] = breach_info
        except Exception as e:
            logger.error(f"Error in breach check: {str(e)}")
            result['breach_info'] = {}
        
        # Get personal information
        try:
            personal_info = osint_scanner.scan_email(email) or {}
            result['personal_info'] = personal_info
        except Exception as e:
            logger.error(f"Error in personal info scan: {str(e)}")
            result['personal_info'] = {}
        
        # Calculate comprehensive risk score
        risk_score = 0
        risk_factors = []
        
        # Domain age risk
        if whois_info.get('age_category') in ['Very New', 'New']:
            risk_score += 20
            risk_factors.append({
                'factor': 'New Domain',
                'description': f"Domain age category: {whois_info.get('age_category')}",
                'score': 20,
                'severity': 'High' if whois_info.get('age_category') == 'Very New' else 'Medium'
            })
        
        # Typosquatting risk
        typo_score = typosquatting_analysis.get('risk_score', 0)
        if typo_score > 50:
            risk_score += 15
            risk_factors.extend(typosquatting_analysis.get('risk_factors', []))
        
        # SSL risk
        ssl_score = ssl_chain_analysis.get('trust_score', 0)
        if ssl_score < 70:
            risk_score += 15
            risk_factors.append({
                'factor': 'SSL Issues',
                'description': 'SSL configuration has security concerns',
                'score': 15,
                'severity': 'Medium'
            })
        
        # Email entropy risk
        if entropy_analysis.get('is_likely_random', False):
            risk_score += 20
            risk_factors.append({
                'factor': 'Suspicious Email Pattern',
                'description': 'Email appears to be randomly generated',
                'score': 20,
                'severity': 'Medium'
            })
        
        # Breach risk
        breach_count = len(breach_info.get('breaches', []))
        if breach_count > 0:
            breach_score = min(breach_count * 10, 30)
            risk_score += breach_score
            risk_factors.append({
                'factor': 'Data Breaches',
                'description': f'Found in {breach_count} data breaches',
                'score': breach_score,
                'severity': 'High' if breach_count > 2 else 'Medium'
            })
        
        # Cap risk score at 100
        result['risk_score'] = min(risk_score, 100)
        result['risk_factors'] = risk_factors
        
        # Determine risk level
        if risk_score >= 70:
            result['risk_level'] = 'High'
        elif risk_score >= 40:
            result['risk_level'] = 'Medium'
        else:
            result['risk_level'] = 'Low'
        
        # Generate risk visualizations
        result['visualizations'] = generate_risk_visualizations(result)
        
        logger.info(f"Enhanced email analysis completed with risk score: {result['risk_score']}")
        return result
        
    except ValueError as ve:
        logger.warning(f"Validation error in email analysis: {str(ve)}")
        raise
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}\n{traceback.format_exc()}")
        raise

def generate_risk_visualizations(analysis_result):
    """Generate data visualizations for the analysis results"""
    visualizations = {}
    
    try:
        # Risk Score Donut Chart
        plt.figure(figsize=(8, 8))
        plt.pie([analysis_result['risk_score'], 100 - analysis_result['risk_score']], 
                colors=['#ff4444' if analysis_result['risk_score'] > 70 else '#ffa000' if analysis_result['risk_score'] > 40 else '#4caf50', '#f0f0f0'],
                labels=['Risk', 'Safe'],
                autopct='%1.1f%%',
                startangle=90)
        plt.title('Overall Risk Score')
        
        # Save to base64
        img_stream = io.BytesIO()
        plt.savefig(img_stream, format='png', bbox_inches='tight', transparent=True)
        img_stream.seek(0)
        visualizations['risk_donut'] = base64.b64encode(img_stream.getvalue()).decode()
        plt.close()
        
        # Risk Factors Bar Chart
        if analysis_result.get('risk_factors'):
            factors = [f['factor'] for f in analysis_result['risk_factors']]
            scores = [f['score'] for f in analysis_result['risk_factors']]
            colors = ['#ff4444' if f['severity'] == 'High' else '#ffa000' if f['severity'] == 'Medium' else '#4caf50' 
                     for f in analysis_result['risk_factors']]
            
            plt.figure(figsize=(10, 6))
            plt.barh(factors, scores, color=colors)
            plt.xlabel('Risk Impact Score')
            plt.title('Risk Factors Analysis')
            
            img_stream = io.BytesIO()
            plt.savefig(img_stream, format='png', bbox_inches='tight', transparent=True)
            img_stream.seek(0)
            visualizations['risk_factors'] = base64.b64encode(img_stream.getvalue()).decode()
            plt.close()
    
    except Exception as e:
        logger.error(f"Error generating visualizations: {str(e)}")
        
    return visualizations

@app.route('/api/scrape-emails', methods=['POST'])
def scrape_emails():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        emails = advanced_scraper.scan_website(url)
        return jsonify({'emails': emails})
    except Exception as e:
        logger.error(f"Error in email scraping: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate-email', methods=['POST'])
async def validate_email():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        validation_result = await enhanced_validator.validate_email(email)
        return jsonify(validation_result)
    except Exception as e:
        logger.error(f"Error in email validation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/assess-threat', methods=['POST'])
def assess_threat():
    try:
        data = request.get_json()
        email_data = data.get('email_data', {})
        social_data = data.get('social_data', {})
        breach_data = data.get('breach_data', {})
        
        threat_report = threat_assessor.generate_threat_report(
            email_data,
            social_data,
            breach_data
        )
        return jsonify(threat_report)
    except Exception as e:
        logger.error(f"Error in threat assessment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test/threat-assessment', methods=['POST'])
def test_threat_assessment():
    try:
        data = request.get_json()
        text = data.get('text', '')
        
        if not text:
            return jsonify({'error': 'No text provided'}), 400
            
        # Test sentiment analysis
        sentiment_result = threat_assessor.analyze_text_sentiment(text)
        
        # Test threat classification
        threat_result = threat_assessor.classify_threat_type(text)
        
        return jsonify({
            'sentiment_analysis': sentiment_result,
            'threat_classification': threat_result
        })
        
    except Exception as e:
        logging.error(f"Error in threat assessment test: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
