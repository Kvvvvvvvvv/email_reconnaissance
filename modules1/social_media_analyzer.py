import requests
import json
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
import re
import time
from modules1.threat_assessment import ThreatAssessment

class SocialMediaAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.threat_assessor = None
        self.session = requests.Session()
        # Set realistic headers to avoid being blocked
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        self.platforms = {
            'github': {
                'url': 'https://api.github.com/users/{}',
                'api_url': 'https://api.github.com/users/{}',
                'web_url': 'https://github.com/{}',
                'check_method': 'api',
                'rate_limit': 1
            },
            'twitter': {
                'url': 'https://twitter.com/{}',
                'api_url': 'https://api.twitter.com/2/users/by/username/{}',
                'web_url': 'https://twitter.com/{}',
                'check_method': 'web',
                'rate_limit': 2
            },
            'instagram': {
                'url': 'https://www.instagram.com/{}',
                'api_url': 'https://www.instagram.com/api/v1/users/web_profile_info/?username={}',
                'web_url': 'https://www.instagram.com/{}',
                'check_method': 'web',
                'rate_limit': 2
            },
            'linkedin': {
                'url': 'https://www.linkedin.com/in/{}',
                'api_url': None,
                'web_url': 'https://www.linkedin.com/in/{}',
                'check_method': 'web',
                'rate_limit': 3
            },
            'facebook': {
                'url': 'https://www.facebook.com/{}',
                'api_url': None,
                'web_url': 'https://www.facebook.com/{}',
                'check_method': 'web',
                'rate_limit': 3
            },
            'reddit': {
                'url': 'https://www.reddit.com/user/{}',
                'api_url': 'https://www.reddit.com/user/{}/about.json',
                'web_url': 'https://www.reddit.com/user/{}',
                'check_method': 'api',
                'rate_limit': 2
            },
            'youtube': {
                'url': 'https://www.youtube.com/@{}',
                'api_url': None,
                'web_url': 'https://www.youtube.com/@{}',
                'check_method': 'web',
                'rate_limit': 2
            },
            'tiktok': {
                'url': 'https://www.tiktok.com/@{}',
                'api_url': None,
                'web_url': 'https://www.tiktok.com/@{}',
                'check_method': 'web',
                'rate_limit': 3
            },
            'discord': {
                'url': 'https://discord.com/api/v9/users/{}',
                'api_url': None,
                'web_url': None,
                'check_method': 'api',
                'rate_limit': 1
            },
            'twitch': {
                'url': 'https://api.twitch.tv/helix/users?login={}',
                'api_url': 'https://api.twitch.tv/helix/users?login={}',
                'web_url': 'https://www.twitch.tv/{}',
                'check_method': 'api',
                'rate_limit': 1
            }
        }

    def get_threat_assessor(self):
        if self.threat_assessor is None:
            self.threat_assessor = ThreatAssessment()
        return self.threat_assessor

    def check_platform_api(self, platform: str, username: str) -> Dict[str, Any]:
        """Check platform using API endpoints for more accurate results"""
        try:
            platform_info = self.platforms[platform]
            if not platform_info['api_url']:
                return self.check_platform_web(platform, username)
            
            url = platform_info['api_url'].format(username)
            
            # Platform-specific headers and parameters
            headers = self.session.headers.copy()
            params = {}
            
            if platform == 'github':
                # GitHub API doesn't require authentication for public user info
                pass
            elif platform == 'reddit':
                headers['User-Agent'] = 'OSPCEmailAnalyzer/1.0'
            elif platform == 'twitch':
                # Twitch requires client ID
                headers['Client-Id'] = 'kimne78kx3ncx6brgo4mv6wki5h1ko'
            
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    exists = self._validate_api_response(data, platform)
                    return {
                        'exists': exists,
                        'url': platform_info['web_url'].format(username) if platform_info['web_url'] else url,
                        'data': data if exists else {},
                        'status_code': response.status_code,
                        'last_checked': datetime.now().isoformat()
                    }
                except json.JSONDecodeError:
                    return {
                        'exists': False,
                        'url': platform_info['web_url'].format(username) if platform_info['web_url'] else url,
                        'error': 'Invalid JSON response',
                        'status_code': response.status_code,
                        'last_checked': datetime.now().isoformat()
                    }
            else:
                return {
                    'exists': False,
                    'url': platform_info['web_url'].format(username) if platform_info['web_url'] else url,
                    'error': f"Status code: {response.status_code}",
                    'status_code': response.status_code,
                    'last_checked': datetime.now().isoformat()
                }
        except Exception as e:
            self.logger.error(f"Error checking {platform} API: {str(e)}")
            return {
                'exists': False,
                'url': platform_info['web_url'].format(username) if platform_info['web_url'] else url,
                'error': str(e),
                'last_checked': datetime.now().isoformat()
            }

    def check_platform_web(self, platform: str, username: str) -> Dict[str, Any]:
        """Check platform using web scraping with improved detection"""
        try:
            platform_info = self.platforms[platform]
            url = platform_info['web_url'].format(username)
            
            # Add platform-specific headers
            headers = self.session.headers.copy()
            if platform == 'instagram':
                headers['X-Requested-With'] = 'XMLHttpRequest'
                headers['Referer'] = 'https://www.instagram.com/'
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            # More sophisticated existence checking
            exists = self._check_profile_exists_advanced(response, platform, username)
            
            return {
                'exists': exists,
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.text),
                'last_checked': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error checking {platform} web: {str(e)}")
            return {
                'exists': False,
                'url': url,
                'error': str(e),
                'last_checked': datetime.now().isoformat()
            }

    def _validate_api_response(self, data: Dict, platform: str) -> bool:
        """Validate API response to determine if profile exists"""
        if platform == 'github':
            return 'login' in data and 'id' in data
        elif platform == 'reddit':
            return 'data' in data and 'name' in data['data']
        elif platform == 'twitch':
            return 'data' in data and len(data['data']) > 0
        return True

    def _check_profile_exists_advanced(self, response, platform: str, username: str) -> bool:
        """Advanced profile existence checking with multiple indicators"""
        if response.status_code != 200:
            return False
        
        content = response.text.lower()
        url = response.url.lower()
        
        # Platform-specific detection logic
        if platform == 'twitter':
            # Twitter redirects to login page for non-existent users
            not_found_indicators = [
                'sorry, that page doesn\'t exist',
                'this account doesn\'t exist',
                'user not found',
                'page not found',
                'this profile doesn\'t exist'
            ]
            # Check if redirected to login or error page
            if 'twitter.com/login' in url or 'twitter.com/i/flow/login' in url:
                return False
            # Check for Twitter's error page structure
            if 'twitter.com/404' in url or 'twitter.com/error' in url:
                return False
            # Check for username in the final URL (Twitter redirects to canonical username)
            if username.lower() in url and 'twitter.com/' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'instagram':
            # Instagram shows specific error pages
            not_found_indicators = [
                'sorry, this page isn\'t available',
                'user not found',
                'page not found',
                'the link you followed may be broken',
                'this account is private'
            ]
            # Check for Instagram's error page structure
            if 'instagram.com/accounts/login' in url:
                return False
            # Check for Instagram's 404 page
            if 'instagram.com/404' in url or 'instagram.com/error' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'instagram.com/' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'linkedin':
            # LinkedIn has specific error patterns
            not_found_indicators = [
                'page not found',
                'profile not found',
                'this profile is not available',
                'the page you\'re looking for doesn\'t exist',
                'profile unavailable'
            ]
            # Check for LinkedIn's error page
            if 'linkedin.com/404' in url or 'linkedin.com/error' in url:
                return False
            # Check for LinkedIn's login redirect
            if 'linkedin.com/login' in url or 'linkedin.com/signup' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'linkedin.com/in/' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'facebook':
            # Facebook has various error states
            not_found_indicators = [
                'this page isn\'t available',
                'page not found',
                'content not found',
                'sorry, this content isn\'t available',
                'this page is not available'
            ]
            # Check for Facebook's error pages
            if 'facebook.com/404' in url or 'facebook.com/error' in url:
                return False
            # Check for Facebook's login redirect
            if 'facebook.com/login' in url or 'facebook.com/signup' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'facebook.com/' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'reddit':
            # Reddit API is more reliable, but check web as backup
            not_found_indicators = [
                'sorry, nobody on reddit goes by that name',
                'user not found',
                'page not found',
                'this user doesn\'t exist'
            ]
            # Check for Reddit's error page
            if 'reddit.com/404' in url or 'reddit.com/error' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'reddit.com/user/' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'youtube':
            # YouTube has specific error patterns
            not_found_indicators = [
                'this channel doesn\'t exist',
                'channel not found',
                'page not found',
                '404',
                'this channel is not available'
            ]
            # Check for YouTube's error page
            if 'youtube.com/404' in url or 'youtube.com/error' in url:
                return False
            # Check for YouTube's login redirect
            if 'youtube.com/login' in url or 'youtube.com/signup' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'youtube.com/@' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        elif platform == 'tiktok':
            # TikTok has specific error patterns
            not_found_indicators = [
                'user not found',
                'this account doesn\'t exist',
                'page not found',
                '404',
                'this user is not available'
            ]
            # Check for TikTok's error page
            if 'tiktok.com/404' in url or 'tiktok.com/error' in url:
                return False
            # Check for TikTok's login redirect
            if 'tiktok.com/login' in url or 'tiktok.com/signup' in url:
                return False
            # Check for username in the final URL
            if username.lower() in url and 'tiktok.com/@' + username.lower() in url:
                return True
            return not any(indicator in content for indicator in not_found_indicators)
        
        # Default fallback - check for reasonable content length and no obvious error indicators
        if len(content) < 1000:  # Too short, likely an error page
            return False
        
        # Check for common error indicators
        common_errors = [
            '404', 'not found', 'error', 'page not found', 'doesn\'t exist',
            'unavailable', 'not available', 'broken', 'invalid'
        ]
        
        if any(error in content for error in common_errors):
            return False
        
        # If we get here, assume it exists (conservative approach)
        return True

    def extract_username_from_email(self, email: str) -> str:
        """Extract and clean username from email address for social media lookup"""
        try:
            # Extract the part before @
            username = email.split('@')[0].lower()
            
            # Remove common email prefixes/suffixes that might not be used in social media
            username = username.replace('admin', '').replace('info', '').replace('contact', '')
            username = username.replace('support', '').replace('help', '').replace('service', '')
            
            # Remove numbers that might be email-specific
            # But keep numbers that are part of the username (like john123)
            if username.isdigit():
                return email.split('@')[0].lower()  # Return original if it's all numbers
            
            # Remove common separators but keep meaningful ones
            username = username.replace('.', '').replace('_', '').replace('-', '')
            
            # If username becomes too short, use original
            if len(username) < 3:
                return email.split('@')[0].lower()
            
            return username
            
        except Exception as e:
            self.logger.error(f"Error extracting username from email: {str(e)}")
            return email.split('@')[0].lower() if '@' in email else email

    def analyze_social_presence(self, username: str) -> Dict[str, Any]:
        """Analyze social media presence with improved accuracy and rate limiting"""
        try:
            self.logger.info(f"Starting social media analysis for: {username}")
            
            # Clean the username for better detection
            clean_username = self.extract_username_from_email(username) if '@' in username else username
            
            results = {
                'username': clean_username,
                'original_username': username,
                'timestamp': datetime.now().isoformat(),
                'platforms': {},
                'summary': {},
                'risk_analysis': {}
            }
            
            # Check each platform with rate limiting
            for platform in self.platforms.keys():
                try:
                    # Rate limiting to avoid being blocked
                    rate_limit = self.platforms[platform]['rate_limit']
                    time.sleep(rate_limit)
                    
                    if self.platforms[platform]['check_method'] == 'api':
                        platform_result = self.check_platform_api(platform, clean_username)
                    else:
                        platform_result = self.check_platform_web(platform, clean_username)
                    
                    results['platforms'][platform] = platform_result
                    
                except Exception as e:
                    self.logger.error(f"Error checking {platform}: {str(e)}")
                    results['platforms'][platform] = {
                        'exists': False,
                        'error': str(e),
                        'last_checked': datetime.now().isoformat()
                    }
            
            # Calculate summary with improved logic
            total_platforms = len(self.platforms)
            found_platforms = sum(1 for p in results['platforms'].values() if p.get('exists', False))
            presence_score = (found_platforms / total_platforms) * 100
            
            results['summary'] = {
                'total_platforms': total_platforms,
                'found_platforms': found_platforms,
                'presence_score': round(presence_score, 2),
                'presence_level': self._get_presence_level(presence_score),
                'platforms_found': [p for p, data in results['platforms'].items() if data.get('exists', False)],
                'platforms_not_found': [p for p, data in results['platforms'].items() if not data.get('exists', False)]
            }
            
            results['risk_analysis'] = self._analyze_social_risk(results)
            return results
            
        except Exception as e:
            self.logger.error(f"Error in social media analysis: {str(e)}")
            return None

    def _get_presence_level(self, score: float) -> str:
        if score >= 70:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'

    def _analyze_social_risk(self, social_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            threat_assessor = self.get_threat_assessor()
            text_content = []
            
            # Extract text content from available profiles
            for platform, data in social_data['platforms'].items():
                if data.get('exists') and 'data' in data:
                    if platform == 'github' and 'bio' in data['data']:
                        text_content.append(data['data']['bio'])
                    elif platform == 'reddit' and 'data' in data['data']:
                        if 'subreddit' in data['data']['data']:
                            text_content.append(data['data']['data']['subreddit'].get('public_description', ''))
            
            risk_factors = []
            
            # Analyze text content if available
            if text_content:
                combined_text = ' '.join(text_content)
                sentiment = threat_assessor.analyze_text_sentiment(combined_text)
                threat_class = threat_assessor.classify_threat_type(combined_text)
                risk_factors.append({
                    'factor': 'Social media content analysis',
                    'sentiment': sentiment,
                    'threat_classification': threat_class,
                    'severity': 'medium' if sentiment['label'] == 'NEGATIVE' else 'low'
                })
            
            # Analyze presence patterns
            presence_score = social_data['summary']['presence_score']
            found_platforms = social_data['summary']['found_platforms']
            
            if presence_score > 80:
                risk_factors.append({
                    'factor': 'High social media presence',
                    'description': f'User has profiles on {found_platforms} out of {social_data["summary"]["total_platforms"]} platforms',
                    'severity': 'low'
                })
            elif presence_score < 10:
                risk_factors.append({
                    'factor': 'Very low social media presence',
                    'description': 'User has minimal online footprint',
                    'severity': 'medium'
                })
            
            # Check for specific high-risk platforms
            high_risk_platforms = ['twitter', 'instagram', 'tiktok']
            found_high_risk = [p for p in high_risk_platforms if p in social_data['summary']['platforms_found']]
            if found_high_risk:
                risk_factors.append({
                    'factor': 'High-visibility social platforms',
                    'description': f'Active on: {", ".join(found_high_risk)}',
                    'severity': 'low'
                })
            
            return {
                'risk_factors': risk_factors,
                'overall_risk_level': self._calculate_overall_risk(risk_factors),
                'recommendations': self._generate_social_recommendations(social_data)
            }
            
        except Exception as e:
            self.logger.error(f"Error in social risk analysis: {str(e)}")
            return {
                'risk_factors': [],
                'overall_risk_level': 'unknown',
                'error': str(e)
            }

    def _calculate_overall_risk(self, risk_factors: List[Dict]) -> str:
        if not risk_factors:
            return 'low'
        
        high_risk_count = sum(1 for factor in risk_factors if factor.get('severity') == 'high')
        medium_risk_count = sum(1 for factor in risk_factors if factor.get('severity') == 'medium')
        
        if high_risk_count > 0:
            return 'high'
        elif medium_risk_count > 2:
            return 'medium'
        else:
            return 'low'

    def _generate_social_recommendations(self, social_data: Dict[str, Any]) -> List[str]:
        recommendations = []
        presence_score = social_data['summary']['presence_score']
        found_platforms = social_data['summary']['found_platforms']
        
        if presence_score < 20:
            recommendations.append("Consider creating professional social media profiles for better online presence")
        elif presence_score > 80:
            recommendations.append("High social media presence detected - ensure privacy settings are properly configured")
        
        if found_platforms > 5:
            recommendations.append("Multiple social media accounts found - consider consolidating or securing accounts")
        
        if found_platforms == 0:
            recommendations.append("No social media presence detected - this may be intentional for privacy")
        
        # Platform-specific recommendations
        platforms_found = social_data['summary']['platforms_found']
        if 'github' in platforms_found:
            recommendations.append("GitHub profile found - ensure repository privacy settings are appropriate")
        if 'linkedin' in platforms_found:
            recommendations.append("LinkedIn profile found - review professional information visibility")
        
        return recommendations

    def get_profile_details(self, platform: str, username: str) -> Dict[str, Any]:
        """Get detailed profile information for a specific platform"""
        try:
            if platform not in self.platforms:
                return {'error': 'Platform not supported'}
            
            # Rate limiting
            rate_limit = self.platforms[platform]['rate_limit']
            time.sleep(rate_limit)
            
            if self.platforms[platform]['check_method'] == 'api':
                return self.check_platform_api(platform, username)
            else:
                return self.check_platform_web(platform, username)
                
        except Exception as e:
            self.logger.error(f"Error getting profile details for {platform}: {str(e)}")
            return {'error': str(e)} 