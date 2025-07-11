import streamlit as st
import re
import requests
import base64
from email import policy
from email.parser import BytesParser

# === VirusTotal Setup ===
API_KEY = "YOURAPIKEYHERE"  # <-- Replace this with your actual API key
HEADERS = {"x-apikey": API_KEY}

def extract_urls(text):
    url_pattern = r'(https?://[^\s"\'<>]+)'
    return re.findall(url_pattern, text)

def scan_url_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=HEADERS
        )
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return malicious + suspicious
        else:
            return -1
    except Exception as e:
        return -1

# === Streamlit App ===
st.title("🛡️ AI-Powered Phishing Email Detector (with VirusTotal URL Scan)")

email_content = st.text_area("📥 Paste the email content here:", height=300)

if st.button("🔍 Check Email"):
    keywords_with_scores = {
        "urgent action required": 5,
        "your account will be suspended": 5,
        "immediate response needed": 4,
        "act now": 3,
        "verify your identity": 4,
        "security alert": 3,
        "account compromised": 5,
        "unauthorized login attempt": 4,
        "you have won": 5,
        "claim your prize": 4,
        "refund available": 3,
        "invoice attached": 2,
        "overdue payment": 3,
        "payment failed": 3,
        "update billing information": 3,
        "click here": 2,
        "confirm your password": 4,
        "reset your account": 3,
        "open attachment": 2,
        "review the document": 1,
        "exclusive offer": 1,
        "free gift": 3,
        "limited time only": 2,
        "verify account": 4,
        "dear customer": 1,
        "prize": 4,
    }

    email_content_lower = email_content.lower()
    total_score = 0
    found_keywords = []
    sender_issues = []
    vt_malicious_urls = []

    phishing_threshold = 5  # You can Adjust if needed

    # Step 1: Parse sender details
    try:
        email_message = BytesParser(policy=policy.default).parsebytes(email_content.encode())
        sender_email = email_message.get('From', '')
        email_match = re.search(r'<(.+?)>|(\S+@\S+\.\S+)', sender_email)
        sender_address = email_match.group(1) or email_match.group(2) if email_match else ''
        
        if sender_address:
            sender_domain = sender_address.split('@')[-1].lower()
            legitimate_domains = ['marksandspencer.co.uk', 'marksandspencer.com']
            if sender_domain not in legitimate_domains:
                if re.search(r'marks.*spencer.*\.(co|org|net)', sender_domain):
                    sender_issues.append(f"Suspicious domain: {sender_domain} (possible typo or fake)")
                    total_score += 3
                else:
                    sender_issues.append(f"Unknown domain: {sender_domain}")
                    total_score += 2

        sender_name = sender_email.split('<')[0].strip() if '<' in sender_email else ''
        if sender_name and sender_address:
            if "M&S" in sender_name and "marksandspencer" not in sender_domain:
                sender_issues.append("Sender name says 'M&S' but domain doesn’t match")
                total_score += 3

        if re.search(r'\b(dear (customer|user|member))\b', email_content_lower):
            sender_issues.append("Generic greeting ('Dear Customer')")
            total_score += 1

        if re.search(r'\b(urgent|immediate|act now)\b', email_content_lower) and not re.search(r'\b(order|account) number\b', email_content_lower):
            sender_issues.append("Urgency without specific details")
            total_score += 2

    except Exception as e:
        st.warning(f"Error parsing email: {e}")

    # Step 2: Keyword Matching
    for keyword, score in keywords_with_scores.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_content_lower):
            total_score += score
            found_keywords.append(keyword)

    # Step 3: Extract & Scan URLs
    urls_found = extract_urls(email_content)
    for url in urls_found:
        result = scan_url_virustotal(url)
        if result > 0:
            vt_malicious_urls.append((url, result))
            total_score += 3

    # Step 4: Display results
    if total_score >= phishing_threshold:
        st.error("⚠️ POTENTIAL PHISHING EMAIL DETECTED!")
        st.write("This email has been flagged due to the following indicators:")

        if found_keywords:
            st.markdown(f"- **Keywords:** {', '.join(found_keywords)}")
        if sender_issues:
            st.markdown(f"- **Sender/Domain Issues:** {', '.join(sender_issues)}")
        if vt_malicious_urls:
            st.markdown("### 🧪 Malicious URLs Detected via VirusTotal")
            for url, engines in vt_malicious_urls:
                st.error(f"- `{url}` was flagged by {engines} engine(s)")
    else:
        st.success("✅ This email appears safe based on current analysis.")
        st.write(f"Keywords found: {len(found_keywords)}")
        if found_keywords or sender_issues:
            st.info(f"Note: Found keywords - {', '.join(found_keywords)} | Sender issues - {', '.join(sender_issues)}")

    if urls_found:
        st.markdown("## 🔗 URLs Found:")
        for url in urls_found:
            st.code(url)

st.markdown("---")
st.markdown("*Disclaimer: This is a basic phishing detector enhanced with VirusTotal. Always verify emails manually when in doubt.*")
