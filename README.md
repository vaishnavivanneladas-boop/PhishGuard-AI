# PhishGuard AI
## Outsmarting the Next-Generation Cyber Attack

PhishGuard AI is a Machine Learning based phishing URL detection system designed to identify potentially malicious URLs and provide an understandable security analysis of the submitted URL.

### Team

- V. Vaishnavi — 160124737094
- B. Vathan Reddy — 160124737100
- Chaitanya Bharathi Institute of Technology
- Information Technology

---

## 🚀 Implemented Features

### 1. Machine Learning Based Phishing Detection
- Uses Machine Learning to classify URLs as **Phishing** or **Legitimate**.
- The primary prediction model is a **Random Forest Classifier**.
- The model is trained using URL-based features extracted directly from URLs.

### 2. URL-Only Analysis
- The system analyzes the submitted URL without downloading or scraping the webpage.
- This makes the prediction process lightweight and suitable for real-time URL analysis.
- The same URL feature extraction logic is shared between training and prediction.

### 3. URL Feature Extraction
PhishGuard AI extracts **19 URL-based features**:

- URL Length
- Domain Length
- IP Address Detection
- Character Continuation Rate
- TLD Length
- Number of Subdomains
- Obfuscation Detection
- Number of Obfuscated Characters
- Obfuscation Ratio
- Number of Letters in URL
- Letter Ratio in URL
- Number of Digits in URL
- Digit Ratio in URL
- Number of `=` Characters
- Number of `?` Characters
- Number of `&` Characters
- Number of Other Special Characters
- Special Character Ratio
- HTTPS Detection

### 4. Multiple Machine Learning Algorithms
The training pipeline compares four classification algorithms:

- Decision Tree
- Random Forest
- Naive Bayes
- K-Nearest Neighbors (KNN)

The best-performing model is selected as the primary deployment model.

### 5. Domain-Grouped Validation
- Uses **GroupShuffleSplit** based on the domain.
- URLs belonging to the same domain are kept within the same train/test group.
- This helps reduce overly optimistic evaluation caused by similar URLs appearing in both training and testing data.

### 6. Risk Level Assessment
The application converts the model's phishing probability into an easy-to-understand risk level:

- **Low Risk**
- **Medium Risk**
- **High Risk**

The risk level is presented visually through a dynamic risk meter.

### 7. URL Intelligence
The application provides detailed information about the submitted URL, including:

- Protocol
- Domain
- Subdomain
- TLD
- Port
- URL length
- Domain length
- URL path
- Query parameters
- Fragment
- IP address status
- Number of subdomains

### 8. URL Structure Analysis
The system breaks the submitted URL into its major components:

- Protocol
- Hostname
- Subdomain
- Registered Domain
- TLD
- Port
- Path
- Query
- Fragment

This helps users understand the structure of the URL being analyzed.

### 9. Security Indicators
PhishGuard AI checks the URL for security-related characteristics such as:

- HTTP vs HTTPS
- Direct IP address usage
- Excessive URL length
- Excessive subdomain depth
- Suspicious keywords
- URL obfuscation
- Special characters
- Query parameters
- Authentication-related wording
- Suspicious URL structure

These indicators are presented as explanatory security information and are separate from the 19 ML model features.

### 10. Suspicious Keyword Detection
The application checks for potentially suspicious words commonly associated with phishing attempts, including:

- login
- signin
- verify
- verification
- account
- secure
- security
- update
- password
- confirm
- payment
- billing
- wallet
- bank
- credential
- authenticate
- unlock
- recover

Detected keywords are displayed to help explain why a URL may require additional caution.

### 11. Phishing Probability
For every submitted URL, the system displays:

- Phishing probability
- Legitimate probability
- Final prediction

This provides more information than simply displaying a binary classification.

### 12. Explainable Prediction
The application includes a **"Why Was This URL Flagged?"** section.

It combines:
- The model's prediction
- Phishing probability
- Detected URL characteristics
- Security indicators
- Suspicious keywords

This makes the result easier for users to understand.

### 13. Security Summary
After scanning a URL, the application provides a concise security summary that highlights important observations from the analysis.

### 14. Extracted ML Features Display
The application allows users to view the **19 features extracted from the submitted URL** before they are passed to the trained model.

This improves transparency and helps demonstrate how the URL is represented for Machine Learning.

### 15. Recent Scan History
The application maintains a recent scan history within the current Streamlit session.

Users can review previously scanned URLs along with their prediction and risk information.

### 16. Professional Interactive Dashboard
The Streamlit interface provides:

- Dark cybersecurity-themed interface
- URL scanning interface
- Prediction result cards
- Probability visualization
- Risk meter
- Expandable analysis sections
- Security summary
- Scan history
- Model performance information

### 17. Model Performance Display
The dashboard displays the performance of the deployed model using:

- Accuracy
- Precision
- Recall
- F1 Score

The current Random Forest model achieved:

| Metric | Score |
|---|---:|
| Accuracy | 99.51% |
| Precision | 99.58% |
| Recall | 99.57% |
| F1 Score | 99.57% |

### 18. Secure Local Prediction
- Submitted URLs are analyzed locally by the application.
- The application does not fetch the submitted webpage.
- No webpage scraping is required for prediction.
- The system therefore avoids sending the submitted URL to an external webpage-analysis service.

### 19. Shared Training and Prediction Pipeline
The training notebook and Streamlit application use the same:

- URL feature extraction logic
- 19 feature definitions
- Feature ordering
- Trained model
- Feature-column metadata

This helps maintain consistency between model training and real-time prediction.

---

## 🧠 Machine Learning Model

The system uses the **PhiUSIIL Phishing URL Dataset**.

The dataset contains URL-related attributes used to train and evaluate multiple Machine Learning algorithms.

The final deployed model is:

**Random Forest Classifier**

Training uses:

- URL-only features
- Domain-grouped train/test split
- Stratified classification labels
- 300 decision trees
- Maximum tree depth of 20
- Minimum samples per leaf of 2
- Balanced class weighting

### Label Mapping

```text
0 → Phishing
1 → Legitimate