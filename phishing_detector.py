import streamlit as st
import re
from email import policy
from email.parser import BytesParser

st.title("AI-Powered Phishing Email Detector (Enhanced)")
email_content = st.text_area("Paste the email content here:")

if st.button("Check Email"):
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

    # Initialize variables
    email_content_lower = email_content.lower()
    total_score = 0
    found_keywords = []
    phishing_threshold = 5
    sender_issues = []

    # Step 1: Parse email to extract sender details
    try:
        email_message = BytesParser(policy=policy.default).parsebytes(email_content.encode())
        sender_email = email_message.get('From', '')
        
        # Extract email address from "From" field (e.g., "M&S Support <support@marks-spencer.co>")
        email_match = re.search(r'<(.+?)>|(\S+@\S+\.\S+)', sender_email)
        sender_address = email_match.group(1) or email_match.group(2) if email_match else ''
        
        # Step 2: Validate sender domain
        if sender_address:
            sender_domain = sender_address.split('@')[-1].lower()
            # List of known legitimate domains (manually curated, free)
            legitimate_domains = ['marksandspencer.co.uk', 'marksandspencer.com']  # Add more as needed
            # Check for domain mismatch or suspicious patterns
            if sender_domain not in legitimate_domains:
                # Check for common phishing domain tricks (e.g., misspellings)
                if any(re.search(r'marks.*spencer.*\.(co|org|net)', sender_domain)):
                    sender_issues.append(f"Suspicious domain: {sender_domain} (possible misspelling or fake domain)")
                    total_score += 3
                else:
                    sender_issues.append(f"Unknown domain: {sender_domain} (not a known M&S domain)")
                    total_score += 2

        # Step 3: Check for social engineering patterns
        # Mismatched sender name and email domain
        sender_name = sender_email.split('<')[0].strip() if '<' in sender_email else ''
        if sender_name and sender_address:
            if "M&S" in sender_name and "marksandspencer" not in sender_domain:
                sender_issues.append("Sender name claims to be M&S, but email domain doesn’t match")
                total_score += 3

        # Generic greeting without personalization
        if re.search(r'\b(dear (customer|user|member))\b', email_content_lower):
            sender_issues.append("Generic greeting ('Dear Customer') without personalization")
            total_score += 1 \

        # Urgency without specifics
        if re.search(r'\b(urgent|immediate|act now)\b', email_content_lower) and not re.search(r'\b(order|account) number\b', email_content_lower):
            sender_issues.append("Urgent call to action without specific details (e.g., no order number)")
            total_score += 2

    except Exception as e:
        st.warning(f"Error parsing email: {e}")

    # Step 4: Existing keyword analysis
    for keyword, score in keywords_with_scores.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_content_lower):
            total_score += score
            found_keywords.append(keyword)

    # Step 5: Output results
    if total_score >= phishing_threshold:
        st.error("⚠️ POTENTIAL PHISHING EMAIL DETECTED!")
        st.write("This email has been flagged as suspicious due to the following indicators:")
        if found_keywords:
            st.markdown(f"- **Keywords:** {', '.join(found_keywords)}")
        if sender_issues:
            st.markdown(f"- **Sender/Context Issues:** {', '.join(sender_issues)}")
        st.write(f"**Suspicious Score:** {total_score} (Threshold: {phishing_threshold})")
        st.warning("Be cautious and avoid clicking links or providing personal information.")
    else:
        st.success("✅ This email appears safe based on keyword and context analysis.")
        st.write(f"Found {len(found_keywords)} common keywords.")
        if found_keywords or sender_issues:
            st.info(f"Note: The following were found: Keywords - {', '.join(found_keywords) if found_keywords else 'None'}; Sender/Context Issues - {', '.join(sender_issues) if sender_issues else 'None'}. Exercise caution.")

st.markdown("---")
st.markdown("*Disclaimer: This is a basic phishing detector and may not catch all sophisticated phishing attempts. Always exercise caution with emails from unknown senders.*")