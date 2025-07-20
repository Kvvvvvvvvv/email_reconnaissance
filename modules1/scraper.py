import requests
import re

def scrape_emails(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        return list(set(re.findall(r"[\w\.-]+@[\w\.-]+", r.text)))
    except:
        return []