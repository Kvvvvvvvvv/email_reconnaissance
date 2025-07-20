import requests
import json
from typing import Dict, List
from datetime import datetime
from bs4 import BeautifulSoup
import re

class EmailVerificationServices:
    def __init__(self):
        self.services = {
            "skymem": {
                "name": "Skymem",
                "url": "http://www.skymem.info/",
                "description": "Email search engine that shows emails indexed from public websites",
                "icon": "fas fa-globe"
            },
            "thatsthem": {
                "name": "That'sThem",
                "url": "https://thatsthem.com/email-lookup",
                "description": "Search email for name, phone, IP, etc.",
                "icon": "fas fa-user"
            },
            "truepeoplesearch": {
                "name": "TruePeopleSearch",
                "url": "https://www.truepeoplesearch.com/",
                "description": "Shows people, phones, addresses linked to email",
                "icon": "fas fa-address-book"
            },
            "emailsherlock": {
                "name": "EmailSherlock",
                "url": "https://www.emailsherlock.com/",
                "description": "Lookup emails for associated identity and social presence",
                "icon": "fas fa-user-secret"
            }
        }

    def check_skymem(self, email: str) -> Dict:
        """Check Skymem for email presence"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(
                f"{self.services['skymem']['url']}srch?q={email}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.find_all('div', class_='result')
                if results:
                    return {
                        "found": True,
                        "sources": [result.text.strip() for result in results],
                        "source": "Skymem"
                    }
            return {"found": False, "source": "Skymem"}
        except Exception as e:
            return {"error": str(e), "source": "Skymem"}

    def check_thatsthem(self, email: str) -> Dict:
        """Check That'sThem for email presence"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(
                f"{self.services['thatsthem']['url']}{email}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Look for common patterns in the response
                name_elements = soup.find_all('h1', class_='name')
                if name_elements:
                    return {
                        "found": True,
                        "name": name_elements[0].text.strip(),
                        "source": "That'sThem"
                    }
            return {"found": False, "source": "That'sThem"}
        except Exception as e:
            return {"error": str(e), "source": "That'sThem"}

    def check_truepeoplesearch(self, email: str) -> Dict:
        """Check TruePeopleSearch for email presence"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(
                f"{self.services['truepeoplesearch']['url']}results?email={email}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.find_all('div', class_='card')
                if results:
                    return {
                        "found": True,
                        "results": [result.text.strip() for result in results],
                        "source": "TruePeopleSearch"
                    }
            return {"found": False, "source": "TruePeopleSearch"}
        except Exception as e:
            return {"error": str(e), "source": "TruePeopleSearch"}

    def check_emailsherlock(self, email: str) -> Dict:
        """Check EmailSherlock for email presence"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(
                f"{self.services['emailsherlock']['url']}search?q={email}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.find_all('div', class_='result')
                if results:
                    return {
                        "found": True,
                        "results": [result.text.strip() for result in results],
                        "source": "EmailSherlock"
                    }
            return {"found": False, "source": "EmailSherlock"}
        except Exception as e:
            return {"error": str(e), "source": "EmailSherlock"}

    def analyze_email(self, email: str) -> Dict:
        """Analyze email using all available free services"""
        results = {
            "email": email,
            "timestamp": datetime.now().isoformat(),
            "services_checked": [],
            "findings": []
        }

        # Check Skymem
        skymem_result = self.check_skymem(email)
        results["services_checked"].append("skymem")
        if skymem_result.get("found"):
            results["findings"].append(skymem_result)

        # Check That'sThem
        thatsthem_result = self.check_thatsthem(email)
        results["services_checked"].append("thatsthem")
        if thatsthem_result.get("found"):
            results["findings"].append(thatsthem_result)

        # Check TruePeopleSearch
        truepeoplesearch_result = self.check_truepeoplesearch(email)
        results["services_checked"].append("truepeoplesearch")
        if truepeoplesearch_result.get("found"):
            results["findings"].append(truepeoplesearch_result)

        # Check EmailSherlock
        emailsherlock_result = self.check_emailsherlock(email)
        results["services_checked"].append("emailsherlock")
        if emailsherlock_result.get("found"):
            results["findings"].append(emailsherlock_result)

        # Calculate risk score based on findings
        risk_score = 0
        risk_factors = []

        # Add points for each service that found information
        for finding in results["findings"]:
            if finding.get("found"):
                risk_score += 15
                risk_factors.append({
                    "factor": f"Information found in {finding['source']}",
                    "score": 15,
                    "severity": "medium"
                })

        # Add points for multiple findings
        if len(results["findings"]) > 1:
            risk_score += 10
            risk_factors.append({
                "factor": "Multiple sources found information",
                "score": 10,
                "severity": "high"
            })

        # Cap the risk score at 100
        results["risk_score"] = min(risk_score, 100)
        results["risk_factors"] = risk_factors
        results["risk_level"] = (
            "critical" if risk_score >= 80 else
            "high" if risk_score >= 60 else
            "medium" if risk_score >= 40 else
            "low"
        )

        return results 