#!/usr/bin/env python3
"""
Test script for the improved social media analyzer
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules1.social_media_analyzer import SocialMediaAnalyzer
import json

def test_social_media_analyzer():
    """Test the social media analyzer with a known username"""
    
    print("🔍 Testing Improved Social Media Analyzer")
    print("=" * 50)
    
    # Initialize the analyzer
    analyzer = SocialMediaAnalyzer()
    
    # Test with a known username (you can change this to your actual username)
    test_username = "testuser123"  # Change this to a username you know exists on some platforms
    
    print(f"Testing username: {test_username}")
    print("This may take a few minutes due to rate limiting...")
    print()
    
    try:
        # Run the analysis
        results = analyzer.analyze_social_presence(test_username)
        
        if results:
            print("✅ Analysis completed successfully!")
            print()
            
            # Display summary
            summary = results.get('summary', {})
            print("📊 SUMMARY:")
            print(f"   Total platforms checked: {summary.get('total_platforms', 0)}")
            print(f"   Platforms found: {summary.get('found_platforms', 0)}")
            print(f"   Presence score: {summary.get('presence_score', 0)}%")
            print(f"   Presence level: {summary.get('presence_level', 'unknown')}")
            print()
            
            # Display platforms found
            platforms_found = summary.get('platforms_found', [])
            platforms_not_found = summary.get('platforms_not_found', [])
            
            if platforms_found:
                print("✅ PLATFORMS FOUND:")
                for platform in platforms_found:
                    print(f"   • {platform.capitalize()}")
                print()
            
            if platforms_not_found:
                print("❌ PLATFORMS NOT FOUND:")
                for platform in platforms_not_found:
                    print(f"   • {platform.capitalize()}")
                print()
            
            # Display detailed platform results
            print("🔍 DETAILED PLATFORM RESULTS:")
            platforms = results.get('platforms', {})
            for platform_name, platform_data in platforms.items():
                status = "✅ FOUND" if platform_data.get('exists') else "❌ NOT FOUND"
                url = platform_data.get('url', 'N/A')
                error = platform_data.get('error', '')
                
                print(f"   {platform_name.capitalize()}: {status}")
                if url and url != 'N/A':
                    print(f"      URL: {url}")
                if error:
                    print(f"      Error: {error}")
                print()
            
            # Display risk analysis
            risk_analysis = results.get('risk_analysis', {})
            if risk_analysis:
                print("⚠️  RISK ANALYSIS:")
                print(f"   Overall risk level: {risk_analysis.get('overall_risk_level', 'unknown')}")
                
                risk_factors = risk_analysis.get('risk_factors', [])
                if risk_factors:
                    print("   Risk factors:")
                    for factor in risk_factors:
                        print(f"      • {factor.get('factor', 'Unknown')} ({factor.get('severity', 'unknown')})")
                
                recommendations = risk_analysis.get('recommendations', [])
                if recommendations:
                    print("   Recommendations:")
                    for rec in recommendations:
                        print(f"      • {rec}")
                print()
            
            # Save results to file for inspection
            with open('social_media_test_results.json', 'w') as f:
                json.dump(results, f, indent=2)
            print("💾 Detailed results saved to 'social_media_test_results.json'")
            
        else:
            print("❌ Analysis failed - no results returned")
            
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_social_media_analyzer() 