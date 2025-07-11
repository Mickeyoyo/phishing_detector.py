# AI-Powered Phishing Email Detector (Keyword + Sender Parsing)
This project is a phishing email detector that uses both keyword analysis and sender context validation to identify potentially malicious emails. Users paste the content of an email into a simple web interface, and the app analyzes it for suspicious keywords and attempts to parse the sender address to spot spoofing or domain tricks.

## 🔍 Features
* Simple User Interface: Built using Streamlit, providing an intuitive web experience.

* Keyword Analysis: Scans for a predefined list of common phishing phrases and urgency-based triggers.

* Sender Parsing & Validation: Extracts and inspects the sender's email address to detect suspicious domains or mismatches.

* Social Engineering Pattern Detection: Flags generic greetings, urgency without context, and spoofed brand names.

* Clear Verdict: Delivers a straightforward "Potential Phishing" or "Appears Safe" result.

* Detailed Feedback: Lists keywords found and issues with sender identity or structure.

## 🚀 How to Use

1. Ensure you have Python and Streamlit installed.
2. Install required libraries:

 ```bash
pip install streamlit
 ```
3. Save the Python script (`phishing_detector.py`) locally.
4. Open a terminal, navigate to the script location, and run:

 ```bash
streamlit run phishing_detector.py
 ```
5. In the web browser that opens:
6. Paste the full email content (`including the "From" line if available`). Click “Check Email.”
7. Review the verdict and indicators returned by the app.

## ⚠️ Limitations

While improved, this detector is still a lightweight tool and has these limitations:

* Not foolproof: May miss more advanced or stealthy phishing attacks.
* False positives: Legitimate emails might trigger certain keywords or patterns.
* Limited parsing: Only basic sender validation is done; no full header analysis or attachment/link inspection.


### 🔄 Latest Update
- Integrated [VirusTotal API](https://virustotal.com) to scan URLs
- Now detects malicious links in phishing emails
- Improved keyword + sender + link analysis for smarter results

## 🔧 Future Enhancements

Integration of full email header parsing (Reply-To, DKIM, SPF checks).

* Addition of attachment/link analysis and threat intelligence integration.
* Machine learning or NLP-based email classification.
* A feedback system to improve detection accuracy over time.

👤 Author
Mickeyoyo
