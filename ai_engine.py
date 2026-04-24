import os
import google.generativeai as genai
from dotenv import load_dotenv
import json

load_dotenv()

# Configure Gemini
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
else:
    model = None

def get_ai_recon(html_content):
    """Analyzes HTML to identify tech stack and suggest initial scan vectors."""
    if not model:
        return {"tech_stack": "Unknown", "vectors": ["Standard SQLi"]}
    
    prompt = f"""
    Analyze the following HTML content of a web page. 
    Identify the technology stack (if possible) and all input fields/forms.
    Return a JSON object with:
    - 'tech_stack': (e.g., 'PHP/MySQL', 'Node.js/MongoDB')
    - 'forms': List of form actions and their fields.
    - 'vectors': List of suggested vulnerability types to test (e.g., 'SQLi', 'XSS').
    
    HTML:
    {html_content[:5000]}  # Limit to avoid token issues
    """
    try:
        response = model.generate_content(prompt)
        # Attempt to parse JSON from AI response
        text = response.text
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception as e:
        print(f"AI Recon error: {e}")
        return {"tech_stack": "Unknown", "forms": [], "vectors": ["SQLi"]}

def ai_judge_response(url, payload, response_text, status_code):
    """Uses AI to determine if an HTTP response indicates a successful exploit."""
    if not model:
        return {"vulnerable": False, "confidence": 0, "reason": "AI not configured"}

    prompt = f"""
    You are a web security expert. Analyze the following HTTP response to determine if the SQL injection payload was successful.
    
    URL: {url}
    Payload: {payload}
    Status Code: {status_code}
    Response Content (truncated):
    {response_text[:3000]}
    
    Respond strictly in JSON format:
    {{
        "vulnerable": true/false,
        "confidence": 0-100,
        "reason": "Explain why you think it is or isn't vulnerable"
    }}
    """
    try:
        response = model.generate_content(prompt)
        text = response.text
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception as e:
        print(f"AI Judge error: {e}")
        return {"vulnerable": False, "confidence": 0, "reason": f"AI Error: {str(e)}"}

def get_remediation(vuln_type, target_tech, sample_code=None):
    """Generates remediation advice and code fixes."""
    if not model:
        return "Configure GEMINI_API_KEY for automated remediation guidance."

    prompt = f"""
    Provide a professional remediation guide for a {vuln_type} vulnerability.
    Target technology stack: {target_tech}
    
    Include:
    1. A brief explanation of the risk.
    2. Best practices to prevent it (e.g., Prepared Statements).
    3. A secure code example in a language relevant to {target_tech}.
    
    Respond in Markdown format.
    """
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error generating remediation: {str(e)}"
