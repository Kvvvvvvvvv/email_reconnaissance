import logging
from transformers import pipeline
import numpy as np
from typing import Dict, List, Any
import json
from datetime import datetime, timedelta

class ThreatAssessment:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            # Initialize sentiment analysis pipeline with DistilBERT
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis",
                model="distilbert-base-uncased-finetuned-sst-2-english",
                revision="af0f99b"
            )
            
            # Initialize zero-shot classification pipeline with BART
            self.zero_shot_classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                revision="c626438"
            )
            
            self.threat_categories = [
                "phishing", "spam", "malware", "social_engineering",
                "data_breach", "credential_theft", "legitimate"
            ]
            
        except Exception as e:
            self.logger.error(f"Error initializing AI models: {str(e)}")
            raise

    def analyze_text_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze the sentiment of text content"""
        try:
            result = self.sentiment_analyzer(text)
            return {
                'label': result[0]['label'],
                'score': float(result[0]['score'])
            }
        except Exception as e:
            self.logger.error(f"Error in sentiment analysis: {str(e)}")
            return {'label': 'UNKNOWN', 'score': 0.0}

    def classify_threat_type(self, content: str) -> Dict[str, Any]:
        """Classify the type of potential threat"""
        try:
            result = self.zero_shot_classifier(
                content,
                candidate_labels=self.threat_categories
            )
            return {
                'labels': result['labels'],
                'scores': [float(score) for score in result['scores']]
            }
        except Exception as e:
            self.logger.error(f"Error in threat classification: {str(e)}")
            return {'labels': [], 'scores': []}

    def analyze_social_media_activity(self, activities: List[Dict]) -> Dict[str, Any]:
        """Analyze social media activities for potential threats"""
        try:
            threat_scores = []
            analysis_results = []

            for activity in activities:
                # Analyze text content
                sentiment = self.analyze_text_sentiment(activity.get('content', ''))
                threat_type = self.classify_threat_type(activity.get('content', ''))

                # Calculate activity risk score
                risk_score = self._calculate_risk_score(
                    sentiment,
                    threat_type,
                    activity.get('metadata', {})
                )

                analysis_results.append({
                    'activity_id': activity.get('id'),
                    'sentiment': sentiment,
                    'threat_classification': threat_type,
                    'risk_score': risk_score
                })
                threat_scores.append(risk_score)

            return {
                'overall_threat_score': np.mean(threat_scores) if threat_scores else 0.0,
                'max_threat_score': max(threat_scores) if threat_scores else 0.0,
                'analysis_results': analysis_results
            }

        except Exception as e:
            self.logger.error(f"Error in social media analysis: {str(e)}")
            return {}

    def _calculate_risk_score(self, 
                            sentiment: Dict[str, Any],
                            threat_class: Dict[str, Any],
                            metadata: Dict[str, Any]) -> float:
        """Calculate a risk score based on various factors"""
        try:
            # Base score from sentiment (0-1)
            sentiment_score = 1.0 - float(sentiment['score']) if sentiment['label'] == 'NEGATIVE' else 0.0
            
            # Threat classification score (0-1)
            threat_score = max(threat_class['scores']) if 'legitimate' not in threat_class['labels'] else 0.0
            
            # Metadata factors
            metadata_score = self._analyze_metadata(metadata)
            
            # Weighted combination
            weights = {
                'sentiment': 0.3,
                'threat': 0.5,
                'metadata': 0.2
            }
            
            final_score = (
                weights['sentiment'] * sentiment_score +
                weights['threat'] * threat_score +
                weights['metadata'] * metadata_score
            )
            
            return min(1.0, max(0.0, final_score))

        except Exception as e:
            self.logger.error(f"Error calculating risk score: {str(e)}")
            return 0.0

    def _analyze_metadata(self, metadata: Dict[str, Any]) -> float:
        """Analyze metadata for risk factors"""
        risk_score = 0.0
        
        # Account age
        if metadata.get('account_age_days', 0) < 30:
            risk_score += 0.3
            
        # Verification status
        if not metadata.get('is_verified', False):
            risk_score += 0.2
            
        # Previous violations
        risk_score += min(0.5, metadata.get('violation_count', 0) * 0.1)
        
        return min(1.0, risk_score)

    def generate_threat_report(self, 
                             email_data: Dict[str, Any],
                             social_data: Dict[str, Any],
                             breach_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive threat assessment report"""
        try:
            report = {
                'timestamp': str(datetime.now()),
                'overall_threat_level': 'LOW',
                'email_analysis': {},
                'social_media_analysis': {},
                'breach_analysis': {},
                'recommendations': []
            }

            # Analyze email content if available
            if email_data.get('content'):
                report['email_analysis'] = {
                    'sentiment': self.analyze_text_sentiment(email_data['content']),
                    'threat_classification': self.classify_threat_type(email_data['content'])
                }

            # Analyze social media data
            if social_data:
                report['social_media_analysis'] = self.analyze_social_media_activity(social_data)

            # Process breach data
            report['breach_analysis'] = self._analyze_breach_data(breach_data)

            # Calculate overall threat level
            threat_level = self._calculate_overall_threat_level(report)
            report['overall_threat_level'] = threat_level

            # Generate recommendations
            report['recommendations'] = self._generate_recommendations(report)

            return report

        except Exception as e:
            self.logger.error(f"Error generating threat report: {str(e)}")
            return {}

    def _analyze_breach_data(self, breach_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze breach data for threat assessment"""
        analysis = {
            'risk_level': 'LOW',
            'total_breaches': 0,
            'recent_breaches': 0,
            'severity_scores': []
        }
        
        if not breach_data:
            return analysis
            
        try:
            recent_threshold = datetime.now() - timedelta(days=365)
            
            analysis['total_breaches'] = len(breach_data.get('breaches', []))
            analysis['recent_breaches'] = sum(
                1 for breach in breach_data.get('breaches', [])
                if datetime.fromisoformat(breach.get('date', '')) > recent_threshold
            )
            
            severity_scores = []
            for breach in breach_data.get('breaches', []):
                score = self._calculate_breach_severity(breach)
                severity_scores.append(score)
            
            analysis['severity_scores'] = severity_scores
            analysis['average_severity'] = np.mean(severity_scores) if severity_scores else 0
            analysis['risk_level'] = self._determine_risk_level(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing breach data: {str(e)}")
            return analysis

    def _calculate_breach_severity(self, breach: Dict[str, Any]) -> float:
        """Calculate severity score for a single breach"""
        severity = 0.0
        
        # Data sensitivity
        sensitive_data_types = ['password', 'credit_card', 'ssn', 'financial']
        severity += sum(0.2 for data_type in breach.get('data_types', [])
                       if data_type in sensitive_data_types)
        
        # Breach size
        affected_users = breach.get('affected_users', 0)
        if affected_users > 1000000:
            severity += 0.3
        elif affected_users > 100000:
            severity += 0.2
        elif affected_users > 10000:
            severity += 0.1
            
        # Recency
        days_since_breach = (datetime.now() - datetime.fromisoformat(breach.get('date', ''))).days
        if days_since_breach < 90:
            severity += 0.3
        elif days_since_breach < 365:
            severity += 0.2
            
        return min(1.0, severity)

    def _determine_risk_level(self, analysis: Dict[str, Any]) -> str:
        """Determine overall risk level based on analysis"""
        if analysis['recent_breaches'] > 2 or analysis['average_severity'] > 0.7:
            return 'HIGH'
        elif analysis['recent_breaches'] > 0 or analysis['average_severity'] > 0.4:
            return 'MEDIUM'
        return 'LOW'

    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on the threat assessment"""
        recommendations = []
        
        # Email-related recommendations
        if report.get('email_analysis'):
            email_threat = report['email_analysis']['threat_classification']
            if 'phishing' in email_threat['labels'][:3]:
                recommendations.append("Enable two-factor authentication on all accounts")
                recommendations.append("Be cautious of unexpected email attachments")
                
        # Social media recommendations
        if report.get('social_media_analysis', {}).get('overall_threat_score', 0) > 0.6:
            recommendations.append("Review and strengthen social media privacy settings")
            recommendations.append("Monitor social media accounts for suspicious activities")
            
        # Breach-related recommendations
        if report.get('breach_analysis', {}).get('risk_level') == 'HIGH':
            recommendations.append("Change passwords for all affected accounts")
            recommendations.append("Monitor credit reports and financial statements")
            recommendations.append("Consider using a password manager")
            
        return recommendations
