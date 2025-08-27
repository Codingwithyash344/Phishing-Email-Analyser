import re
import requests
from email import policy
from email.parser import BytesParser

class PhishingEmailAnalyzer:
    def __init__(self):
        self.phishing_keywords = ['urgent', 'verify', 'account', 'suspended', 'login', 'update', 'confirm']

    def parse_email(self, email_file):
        with open(email_file, 'rb') as f:
            email = BytesParser(policy=policy.default).parse(f)
        return email

    def check_subject(self, subject):
        for keyword in self.phishing_keywords:
            if keyword in subject.lower():
                return True
        return False

    def check_links(self, body):
        urls = re.findall(r'(https?://[^\s]+)', body)
        for url in urls:
            if self.is_phishing_url(url):
                return True
        return False

    def is_phishing_url(self, url):
        # Simple check: You can enhance this with a more sophisticated URL checking
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return False  # URL is reachable
            else:
                return True  # URL is not reachable, could be suspicious
        except requests.RequestException:
            return True  # URL is unreachable, could be suspicious

    def analyze_email(self, email_file):
        email = self.parse_email(email_file)
        subject = email['subject']
        body = email.get_body(preferencelist=('plain')).get_content()

        print(f"Analyzing email: {email_file}")
        if self.check_subject(subject):
            print("Warning: Subject contains phishing keywords.")
        else:
            print("Subject is clean.")

        if self.check_links(body):
            print("Warning: Email contains suspicious links.")
        else:
            print("No suspicious links found.")

if __name__ == "__main__":
    analyzer = PhishingEmailAnalyzer()
    email_file = 'sample_email.eml'  # Replace with your email file
    analyzer.analyze_email(email_file)
