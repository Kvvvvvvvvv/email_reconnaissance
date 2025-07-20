from flask import Flask, render_template, request, jsonify
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
from modules1.social_media_analyzer import SocialMediaAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize modules with lazy loading
osint_scanner = None
website_checker = None
email_verifier = None
breach_checker = None
news_feed = None
advanced_scraper = None
enhanced_validator = None
threat_assessor = None
social_media_analyzer = None

def get_osint_scanner():
    global osint_scanner
    if osint_scanner is None:
        osint_scanner = OSINTScanner()
    return osint_scanner

def get_website_checker():
    global website_checker
    if website_checker is None:
        website_checker = WebsiteChecker()
    return website_checker

def get_email_verifier():
    global email_verifier
    if email_verifier is None:
        email_verifier = EmailVerificationServices()
    return email_verifier

def get_breach_checker():
    global breach_checker
    if breach_checker is None:
        breach_checker = BreachChecker()
    return breach_checker

def get_news_feed():
    global news_feed
    if news_feed is None:
        news_feed = NewsFeed()
    return news_feed

def get_advanced_scraper():
    global advanced_scraper
    if advanced_scraper is None:
        advanced_scraper = AdvancedEmailScraper()
    return advanced_scraper

def get_enhanced_validator():
    global enhanced_validator
    if enhanced_validator is None:
        enhanced_validator = EnhancedEmailValidator()
    return enhanced_validator

def get_threat_assessor():
    global threat_assessor
    if threat_assessor is None:
        threat_assessor = ThreatAssessment()
    return threat_assessor

def get_social_media_analyzer():
    global social_media_analyzer
    if social_media_analyzer is None:
        social_media_analyzer = SocialMediaAnalyzer()
    return social_media_analyzer

logger.info("App initialized with lazy loading - modules will be loaded when needed")

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
            exists = get_website_checker().check_url(url)
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
        breach_info = get_breach_checker().check_breaches(username)
        
        # Get OSINT information
        osint_info = get_osint_scanner().scan_username(username)
        
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
    email_info = None
    error_message = None
    
    try:
        # Get news items
        news_items = get_news_feed().fetch_news()
    except Exception as e:
        logger.error(f"Error fetching news: {str(e)}")
        news_items = []

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
                error_message = f"Error analyzing email: {str(e)}"

    return render_template('index.html',
                         app_name="OSPC Username Recon",
                         app_version="1.0.0",
                         now=datetime.now(),
                         email_info=email_info,
                         error_message=error_message,
                         news_items=news_items)

def is_valid_email(email):
    """Check if the email format is valid"""
    return EmailUtils.validate_email(email)

def analyze_domain(domain):
    """Analyze domain characteristics"""
    try:
        logger.info(f"Analyzing domain: {domain}")
        result = {
            'domain': domain,
            'domain_info': {
                'type': 'Unknown',
                'company': 'Unknown',
                'age': 'Unknown',
                'registrar': 'Unknown'
            }
        }
        
        # Determine domain type
        if domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
            result['domain_info']['type'] = 'personal'
            result['domain_info']['company'] = domain.split('.')[0].title()
        elif domain.endswith('.edu'):
            result['domain_info']['type'] = 'educational'
            result['domain_info']['company'] = 'Educational Institution'
        elif domain.endswith('.gov'):
            result['domain_info']['type'] = 'government'
            result['domain_info']['company'] = 'Government'
        elif domain.endswith('.org'):
            result['domain_info']['type'] = 'organization'
            result['domain_info']['company'] = 'Non-profit Organization'
        else:
            result['domain_info']['type'] = 'business'
            result['domain_info']['company'] = domain.split('.')[0].title()
        
        # Mock domain age
        import random
        ages = ['1-5 years', '5-10 years', '10+ years']
        result['domain_info']['age'] = random.choice(ages)
        
        # Mock registrar
        registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Cloudflare']
        result['domain_info']['registrar'] = random.choice(registrars)
        
        logger.info("Domain analysis completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in domain analysis: {str(e)}")
        return {
            'domain': domain,
            'domain_info': {
                'type': 'Unknown',
                'company': 'Unknown',
                'age': 'Unknown',
                'registrar': 'Unknown'
            }
        }

def analyze_email_pattern(email):
    """Analyze email pattern characteristics"""
    try:
        logger.info(f"Analyzing email pattern: {email}")
        
        username, domain = email.split('@')
        
        # Pattern analysis
        score = 0
        pattern_type = 'standard'
        has_special_chars = False
        is_random = False
        has_common_name = False
        
        # Check for special characters
        special_chars = re.findall(r'[._-]', username)
        if special_chars:
            has_special_chars = True
            score += 20
        
        # Check for numbers
        numbers = re.findall(r'\d', username)
        if numbers:
            score += 15
        
        # Check for randomness (mixed case, numbers, special chars)
        if re.search(r'[A-Z]', username) and re.search(r'[a-z]', username):
            score += 10
        
        # Check for common names
        common_names = ['john', 'jane', 'admin', 'user', 'test', 'info', 'contact']
        if username.lower() in common_names:
            has_common_name = True
            score -= 10
            pattern_type = 'common'
        
        # Determine pattern type
        if len(username) > 15:
            pattern_type = 'long'
            score += 5
        elif len(username) < 5:
            pattern_type = 'short'
            score -= 5
        
        # Check for random string patterns
        if re.match(r'^[a-zA-Z0-9]{8,}$', username) and not has_common_name:
            is_random = True
            pattern_type = 'random'
            score += 25
        
        logger.info("Pattern analysis completed successfully")
        
        return {
            'score': min(score, 100),
            'type': pattern_type,
            'has_special_chars': has_special_chars,
            'is_random': is_random,
            'has_common_name': has_common_name
        }
        
    except Exception as e:
        logger.error(f"Error in pattern analysis: {str(e)}")
        return {
            'score': 0,
            'type': 'Unknown',
            'has_special_chars': False,
            'is_random': False,
            'has_common_name': False
        }

def get_email_analysis(email):
    """Get comprehensive email analysis"""
    try:
        logger.info(f"Starting email analysis for: {email}")
        
        # Validate email format
        if not is_valid_email(email):
            logger.warning(f"Invalid email format: {email}")
            return None
            
        # Get domain analysis
        domain = email.split('@')[1]
        domain_analysis = analyze_domain(domain)
        logger.info(f"Domain analysis completed for {domain}")
        
        # Get email pattern analysis
        pattern_analysis = analyze_email_pattern(email)
        logger.info("Email pattern analysis completed")
        
        # Check for breaches with enhanced analysis
        breach_info = get_breach_checker().check_breaches(email)
        logger.info(f"Enhanced breach check completed: {breach_info['breach_count']} breaches found")
        
        # Get personal information
        personal_info = get_osint_scanner().scan_email(email)
        logger.info("Personal information scan completed")
        
        # Check website presence
        website_presence = get_website_checker().check_url(email)
        logger.info("Website presence check completed")
        
        # Extract username for social media analysis
        username = email.split('@')[0]
        social_media_analysis = get_social_media_analyzer().analyze_social_presence(username)
        logger.info("Social media analysis completed")
        
        # Calculate risk score with enhanced factors
        risk_score = 0
        risk_factors = []
        
        # Factor 1: Breach presence (30 points max)
        if breach_info['breach_count'] > 0:
            breach_score = min(breach_info['breach_count'] * 8, 30)
            risk_score += breach_score
            risk_factors.append({
                'factor': f"Found in {breach_info['breach_count']} data breaches",
                'score': breach_score,
                'severity': 'high' if breach_score > 20 else 'medium'
            })
            
            # Add breach severity factor
            if breach_info.get('severity_level') == 'critical':
                risk_score += 15
                risk_factors.append({
                    'factor': "Critical severity breaches detected",
                    'score': 15,
                    'severity': 'critical'
                })
        
        # Factor 2: Domain type (15 points max)
        domain_score = 0
        if domain_analysis['domain_info']['type'] == 'personal':
            domain_score = 15
        elif domain_analysis['domain_info']['type'] == 'business':
            domain_score = 8
        risk_score += domain_score
        risk_factors.append({
            'factor': f"Domain type: {domain_analysis['domain_info']['type']}",
            'score': domain_score,
            'severity': 'high' if domain_score > 10 else 'medium'
        })
        
        # Factor 3: Email pattern complexity (15 points max)
        pattern_score = pattern_analysis['score']
        risk_score += pattern_score
        risk_factors.append({
            'factor': f"Email pattern complexity: {pattern_analysis['type']}",
            'score': pattern_score,
            'severity': 'high' if pattern_score > 10 else 'medium'
        })
        
        # Factor 4: Social media presence (20 points max)
        if social_media_analysis and social_media_analysis.get('summary'):
            social_score = social_media_analysis['summary']['presence_score'] * 0.2
            risk_score += social_score
            risk_factors.append({
                'factor': f"Social media presence: {social_media_analysis['summary']['presence_level']}",
                'score': social_score,
                'severity': 'medium'
            })
            
            # Add social media risk factors
            if social_media_analysis.get('risk_analysis', {}).get('risk_factors'):
                for risk_factor in social_media_analysis['risk_analysis']['risk_factors']:
                    if risk_factor.get('severity') == 'high':
                        risk_score += 5
                        risk_factors.append({
                            'factor': risk_factor.get('factor', 'Social media risk'),
                            'score': 5,
                            'severity': 'high'
                        })
        
        # Factor 5: Website presence (10 points max)
        if website_presence['found_accounts']:
            presence_score = min(len(website_presence['found_accounts']) * 2, 10)
            risk_score += presence_score
            risk_factors.append({
                'factor': f"Found on {len(website_presence['found_accounts'])} platforms",
                'score': presence_score,
                'severity': 'medium'
            })
        
        # Factor 6: Breach risk analysis (10 points max)
        if breach_info.get('risk_analysis', {}).get('overall_risk_score'):
            breach_risk_score = min(breach_info['risk_analysis']['overall_risk_score'] * 0.1, 10)
            risk_score += breach_risk_score
            risk_factors.append({
                'factor': f"Breach risk score: {breach_info['risk_analysis']['overall_risk_score']}",
                'score': breach_risk_score,
                'severity': 'high' if breach_risk_score > 5 else 'medium'
            })
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        logger.info(f"Enhanced risk assessment completed. Score: {risk_score}, Level: {risk_level}")
        
        return {
            'timestamp': datetime.now().isoformat(),
            'email': email,
            'domain_analysis': domain_analysis,
            'pattern_analysis': pattern_analysis,
            'breach_info': breach_info,
            'personal_info': personal_info,
            'website_presence': website_presence,
            'social_media_analysis': social_media_analysis,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
        
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        raise

@app.route('/api/scrape-emails', methods=['POST'])
def scrape_emails():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        emails = get_advanced_scraper().scan_website(url)
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
            
        validation_result = await get_enhanced_validator().validate_email(email)
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
        
        threat_report = get_threat_assessor().generate_threat_report(
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
        sentiment_result = get_threat_assessor().analyze_text_sentiment(text)
        
        # Test threat classification
        threat_result = get_threat_assessor().classify_threat_type(text)
        
        return jsonify({
            'sentiment_analysis': sentiment_result,
            'threat_classification': threat_result
        })
        
    except Exception as e:
        logging.error(f"Error in threat assessment test: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/social-media-analysis', methods=['POST'])
def social_media_analysis():
    """Analyze social media presence for a username"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        
        if not username:
            return jsonify({'error': 'Username is required'}), 400
            
        analysis_result = get_social_media_analyzer().analyze_social_presence(username)
        
        if analysis_result:
            return jsonify(analysis_result)
        else:
            return jsonify({'error': 'Analysis failed'}), 500
            
    except Exception as e:
        logger.error(f"Error in social media analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enhanced-email-validation', methods=['POST'])
async def enhanced_email_validation():
    """Enhanced email validation with multiple checks"""
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        validation_result = await get_enhanced_validator().validate_email(email)
        
        if validation_result:
            return jsonify(validation_result)
        else:
            return jsonify({'error': 'Validation failed'}), 500
            
    except Exception as e:
        logger.error(f"Error in enhanced email validation: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/comprehensive-breach-check', methods=['POST'])
def comprehensive_breach_check():
    """Comprehensive breach checking with risk analysis"""
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
            
        breach_result = get_breach_checker().check_breaches(email)
        
        return jsonify(breach_result)
        
    except Exception as e:
        logger.error(f"Error in comprehensive breach check: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/password-strength-check', methods=['POST'])
def password_strength_check():
    """Check password strength and if it's been compromised"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
            
        strength_result = get_breach_checker().check_password_strength(password)
        
        return jsonify(strength_result)
        
    except Exception as e:
        logger.error(f"Error in password strength check: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai-threat-analysis', methods=['POST'])
def ai_threat_analysis():
    """AI-powered threat analysis for email content"""
    try:
        data = request.get_json()
        email_content = data.get('email_content', '')
        email_address = data.get('email_address', '')
        
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400
            
        # Perform sentiment analysis
        sentiment_result = get_threat_assessor().analyze_text_sentiment(email_content)
        
        # Perform threat classification
        threat_result = get_threat_assessor().classify_threat_type(email_content)
        
        # Generate comprehensive threat report
        threat_report = get_threat_assessor().generate_threat_report(
            {'content': email_content, 'email': email_address},
            {},
            {}
        )
        
        return jsonify({
            'sentiment_analysis': sentiment_result,
            'threat_classification': threat_result,
            'threat_report': threat_report
        })
        
    except Exception as e:
        logger.error(f"Error in AI threat analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 