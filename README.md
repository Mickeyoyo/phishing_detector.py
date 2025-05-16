# AI-Powered Phishing Email Detector (Keyword Based)

This project is a simple phishing email detector that utilizes a keyword-based approach to identify potentially malicious emails. Users can paste the content of an email into a web interface, and the application analyzes it for the presence of common phishing keywords and phrases.

## Features

* imple User Interface: Built using Streamlit, providing an easy-to-use web application.
* Keyword Analysis: etects phishing attempts by identifying a predefined list of suspicious keywords within the email content.
* Clear Verdict: Provides a straightforward "Phishing" or "Safe" classification.
* Keyword Explanation: When an email is flagged as potential phishing, the application displays the keywords that triggered the classification.

## How to Use

1.  Ensure you have Python installed on your system.
2.  Install the necessary library:
    ```bash
    pip install streamlit
    ```
3.  Save the Python script (`phishing_detector.py`) to your local machine.
4.  Open your command prompt or terminal, navigate to the directory where you saved the file, and run:
    ```bash
    streamlit run phishing_detector.py
    ```
5.  A web browser will open with the application. Paste the email content you want to check into the text area and click "Check Email."

## Limitations

This is a basic implementation that relies solely on keyword detection. It has the following limitations:

* Not foolproof: Sophisticated phishing emails may not contain obvious keywords.
* False positives: Legitimate emails might contain some of the flagged keywords.
* Lack of advanced analysis: Does not perform link analysis, header inspection, or other more advanced phishing detection techniques.

## Future Enhancements

Potential future improvements could include:

* Implementing more sophisticated techniques like machine learning or using the OpenAI API for content analysis.
* Adding link analysis to check for suspicious URLs.
* Improving the keyword list and scoring mechanism.
* Providing more detailed explanations of why an email might be suspicious.

## Author

Ibikunle Michael/Mickeyoyo
