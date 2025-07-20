import requests
from bs4 import BeautifulSoup
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import tld

class AdvancedEmailScraper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.visited_urls = set()
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def extract_emails_from_text(self, text):
        """Extract email addresses from text using regex"""
        return set(self.email_pattern.findall(text))

    def is_valid_url(self, url):
        """Check if URL is valid and belongs to the same domain"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def get_domain_from_url(self, url):
        """Extract base domain from URL"""
        try:
            return tld.get_fld(url)
        except:
            return urlparse(url).netloc

    async def scrape_url(self, url, max_depth=2, current_depth=0):
        """Scrape a URL for email addresses and recursively check linked pages"""
        if current_depth > max_depth or url in self.visited_urls:
            return set()

        self.visited_urls.add(url)
        emails = set()

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract emails from visible text
                emails.update(self.extract_emails_from_text(response.text))
                
                # Extract emails from meta tags
                for meta in soup.find_all('meta'):
                    content = meta.get('content', '')
                    emails.update(self.extract_emails_from_text(content))
                
                # Extract emails from links
                for link in soup.find_all('a'):
                    href = link.get('href', '')
                    if href.startswith('mailto:'):
                        emails.add(href[7:])
                    
                # Recursively check linked pages
                if current_depth < max_depth:
                    links = [urljoin(url, link.get('href')) for link in soup.find_all('a')]
                    valid_links = [link for link in links if self.is_valid_url(link) 
                                 and self.get_domain_from_url(link) == self.get_domain_from_url(url)]
                    
                    with ThreadPoolExecutor(max_workers=5) as executor:
                        for link in valid_links:
                            if link not in self.visited_urls:
                                future = executor.submit(self.scrape_url, link, max_depth, current_depth + 1)
                                emails.update(future.result())

        except Exception as e:
            self.logger.error(f"Error scraping {url}: {str(e)}")

        return emails

    def scan_website(self, url, max_depth=2):
        """Main method to scan a website for email addresses"""
        try:
            emails = self.scrape_url(url, max_depth)
            return list(emails)
        except Exception as e:
            self.logger.error(f"Error in scan_website: {str(e)}")
            return []
