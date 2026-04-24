import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_target(url):
    """
    Crawls the target URL to find forms and input fields.
    Returns a list of 'testable' objects.
    """
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        testable_elements = []
        
        # Find all forms
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                type_ = input_tag.get('type', 'text')
                if name:
                    inputs.append({'name': name, 'type': type_})
            
            testable_elements.append({
                'type': 'form',
                'action': urljoin(url, action) if action else url,
                'method': method,
                'inputs': inputs
            })
            
        # Find URL parameters (if any already in the URL)
        parsed = urlparse(url)
        if parsed.query:
            testable_elements.append({
                'type': 'url_params',
                'url': url,
                'params': parsed.query
            })
            
        return testable_elements, response.text
    except Exception as e:
        print(f"Crawling error: {e}")
        return [], ""
