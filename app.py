import streamlit as st
import pandas as pd
import json
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# FILE PATHS
# ============================================================

MODEL_PATH = "models/phishguard_random_forest.json"
FEATURE_PATH = "models/feature_columns.json"


# ============================================================
# LOAD RANDOM FOREST
# ============================================================

with open(MODEL_PATH, "r", encoding="utf-8") as f:
    forest = json.load(f)

with open(FEATURE_PATH, "r", encoding="utf-8") as f:
    feature_columns = json.load(f)


# ============================================================
# URL FEATURES
# ============================================================

def extract_url_features(url):

    original_url = url

    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.split(":")[0]

    letters = sum(c.isalpha() for c in original_url)
    digits = sum(c.isdigit() for c in original_url)
    special = sum(not c.isalnum() for c in original_url)

    subdomains = max(
        0,
        len(domain.split(".")) - 2
    )

    features = {

        "URLLength":
            len(original_url),

        "DomainLength":
            len(domain),

        "IsDomainIP":
            int(
                bool(
                    re.fullmatch(
                        r"\d{1,3}(\.\d{1,3}){3}",
                        domain
                    )
                )
            ),

        "TLDLength":
            len(domain.split(".")[-1])
            if "." in domain else 0,

        "NoOfSubDomain":
            subdomains,

        "HasObfuscation":
            int("%" in original_url or "@" in original_url),

        "NoOfObfuscatedChar":
            original_url.count("%"),

        "ObfuscationRatio":
            original_url.count("%") /
            max(len(original_url), 1),

        "NoOfLettersInURL":
            letters,

        "LetterRatioInURL":
            letters /
            max(len(original_url), 1),

        "NoOfDegitsInURL":
            digits,

        "DegitRatioInURL":
            digits /
            max(len(original_url), 1),

        "NoOfEqualsInURL":
            original_url.count("="),

        "NoOfQMarkInURL":
            original_url.count("?"),

        "NoOfAmpersandInURL":
            original_url.count("&"),

        "NoOfOtherSpecialCharsInURL":
            special,

        "SpacialCharRatioInURL":
            special /
            max(len(original_url), 1),

        "IsHTTPS":
            int(
                parsed.scheme.lower() == "https"
            ),

        "NoOfURLRedirect":
            max(
                0,
                original_url.count("//") - 1
            ),

        "NoOfSelfRedirect":
            0
    }

    return features, url, domain


# ============================================================
# WEBPAGE FEATURES
# ============================================================

def extract_webpage_features(url):

    features = {}

    try:

        headers = {
            "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True
        )

        html = response.text

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        final_url = response.url

        parsed = urlparse(final_url)

        domain = parsed.netloc

        # ------------------------------------------------
        # HTML statistics
        # ------------------------------------------------

        lines = html.splitlines()

        features["LineOfCode"] = len(lines)

        features["LargestLineLength"] = (
            max(
                [len(line) for line in lines],
                default=0
            )
        )

        # ------------------------------------------------
        # TITLE
        # ------------------------------------------------

        title = soup.title.string.strip() if soup.title and soup.title.string else ""

        features["HasTitle"] = int(bool(title))

        # ------------------------------------------------
        # DESCRIPTION
        # ------------------------------------------------

        description = soup.find(
            "meta",
            attrs={"name": re.compile("^description$", re.I)}
        )

        features["HasDescription"] = int(
            description is not None
        )

        # ------------------------------------------------
        # FAVICON
        # ------------------------------------------------

        favicon = soup.find(
            "link",
            rel=lambda x:
            x and "icon" in str(x).lower()
        )

        features["HasFavicon"] = int(
            favicon is not None
        )

        # ------------------------------------------------
        # RESPONSIVE DESIGN
        # ------------------------------------------------

        viewport = soup.find(
            "meta",
            attrs={
                "name":
                re.compile("^viewport$", re.I)
            }
        )

        features["IsResponsive"] = int(
            viewport is not None
        )

        # ------------------------------------------------
        # IMAGES
        # ------------------------------------------------

        images = soup.find_all("img")

        features["NoOfImage"] = len(images)

        # ------------------------------------------------
        # CSS
        # ------------------------------------------------

        css_links = soup.find_all(
            "link",
            href=True
        )

        css_count = 0

        for link in css_links:

            href = str(
                link.get("href", "")
            ).lower()

            if ".css" in href:
                css_count += 1

        css_count += len(
            soup.find_all("style")
        )

        features["NoOfCSS"] = css_count

        # ------------------------------------------------
        # JAVASCRIPT
        # ------------------------------------------------

        scripts = soup.find_all("script")

        features["NoOfJS"] = len(scripts)

        # ------------------------------------------------
        # IFRAMES
        # ------------------------------------------------

        features["NoOfiFrame"] = len(
            soup.find_all("iframe")
        )

        # ------------------------------------------------
        # FORMS
        # ------------------------------------------------

        forms = soup.find_all("form")

        external_forms = 0

        for form in forms:

            action = form.get("action", "")

            if action:

                absolute_action = urljoin(
                    final_url,
                    action
                )

                action_domain = urlparse(
                    absolute_action
                ).netloc

                if (
                    action_domain
                    and action_domain != domain
                ):
                    external_forms += 1

        features["HasExternalFormSubmit"] = int(
            external_forms > 0
        )

        # ------------------------------------------------
        # PASSWORD FIELD
        # ------------------------------------------------

        password_fields = soup.find_all(
            "input",
            attrs={"type": re.compile(
                "^password$",
                re.I
            )}
        )

        features["HasPasswordField"] = int(
            len(password_fields) > 0
        )

        # ------------------------------------------------
        # HIDDEN FIELDS
        # ------------------------------------------------

        hidden_fields = soup.find_all(
            "input",
            attrs={"type": re.compile(
                "^hidden$",
                re.I
            )}
        )

        features["HasHiddenFields"] = int(
            len(hidden_fields) > 0
        )

        # ------------------------------------------------
        # SUBMIT BUTTON
        # ------------------------------------------------

        submit_buttons = soup.find_all(
            ["button", "input"]
        )

        has_submit = False

        for element in submit_buttons:

            element_type = str(
                element.get("type", "")
            ).lower()

            text = element.get_text(
                " ",
                strip=True
            ).lower()

            if (
                element_type == "submit"
                or "submit" in text
                or "login" in text
                or "sign in" in text
            ):
                has_submit = True
                break

        features["HasSubmitButton"] = int(
            has_submit
        )

        # ------------------------------------------------
        # SOCIAL NETWORK
        # ------------------------------------------------

        social_words = [
            "facebook",
            "instagram",
            "twitter",
            "linkedin",
            "youtube",
            "tiktok"
        ]

        html_lower = html.lower()

        features["HasSocialNet"] = int(
            any(
                word in html_lower
                for word in social_words
            )
        )

        # ------------------------------------------------
        # COPYRIGHT
        # ------------------------------------------------

        features["HasCopyrightInfo"] = int(
            "copyright" in html_lower
            or "©" in html
        )

        # ------------------------------------------------
        # POPUPS
        # ------------------------------------------------

        popup_words = [
            "window.open",
            "alert(",
            "popup"
        ]

        features["NoOfPopup"] = sum(
            html_lower.count(word)
            for word in popup_words
        )

        # ------------------------------------------------
        # REFERENCES
        # ------------------------------------------------

        links = soup.find_all(
            "a",
            href=True
        )

        self_refs = 0
        external_refs = 0

        for link in links:

            href = link.get("href", "")

            if not href:
                continue

            absolute = urljoin(
                final_url,
                href
            )

            target_domain = urlparse(
                absolute
            ).netloc

            if not target_domain:
                self_refs += 1

            elif target_domain == domain:
                self_refs += 1

            else:
                external_refs += 1

        features["NoOfSelfRef"] = self_refs

        features["NoOfExternalRef"] = external_refs

        features["NoOfEmptyRef"] = sum(
            1
            for link in links
            if link.get("href", "").strip()
            in ["", "#", "javascript:void(0)"]
        )

        return features, final_url, True

    except Exception as e:

        return {
            "LineOfCode": 0,
            "LargestLineLength": 0,
            "HasTitle": 0,
            "HasDescription": 0,
            "HasFavicon": 0,
            "IsResponsive": 0,
            "NoOfImage": 0,
            "NoOfCSS": 0,
            "NoOfJS": 0,
            "NoOfiFrame": 0,
            "HasExternalFormSubmit": 0,
            "HasPasswordField": 0,
            "HasHiddenFields": 0,
            "HasSubmitButton": 0,
            "HasSocialNet": 0,
            "HasCopyrightInfo": 0,
            "NoOfPopup": 0,
            "NoOfSelfRef": 0,
            "NoOfExternalRef": 0,
            "NoOfEmptyRef": 0
        }, url, False


# ============================================================
# DECISION TREE PREDICTION
# ============================================================

def predict_tree(tree, values):

    node = 0

    while tree["children_left"][node] != -1:

        feature = tree["feature"][node]

        threshold = tree["threshold"][node]

        if values[feature] <= threshold:

            node = tree["children_left"][node]

        else:

            node = tree["children_right"][node]

    counts = tree["value"][node][0]

    return 0 if counts[0] > counts[1] else 1


# ============================================================
# RANDOM FOREST PREDICTION
# ============================================================

def predict_forest(features):

    values = [
        float(
            features.get(
                column,
                0
            )
        )
        for column in forest["features"]
    ]

    predictions = []

    for tree in forest["trees"]:

        prediction = predict_tree(
            tree,
            values
        )

        predictions.append(
            prediction
        )

    phishing_votes = predictions.count(0)

    legitimate_votes = predictions.count(1)

    if phishing_votes > legitimate_votes:

        prediction = 0

        confidence = (
            phishing_votes /
            len(predictions)
        )

    else:

        prediction = 1

        confidence = (
            legitimate_votes /
            len(predictions)
        )

    return prediction, confidence


# ============================================================
# USER INTERFACE
# ============================================================

st.title("🛡️ PhishGuard AI")

st.subheader(
    "Outsmarting the Next-Generation Cyber Attack"
)

st.write(
    "Machine Learning Based Phishing URL Detection"
)

st.divider()

url = st.text_input(
    "Enter a website URL",
    placeholder="https://example.com"
)


if st.button(
    "🔍 Analyze Website",
    type="primary"
):

    if not url.strip():

        st.warning(
            "Please enter a website URL."
        )

    else:

        with st.spinner(
            "Analyzing URL and webpage..."
        ):

            url_features, normalized_url, domain = (
                extract_url_features(
                    url.strip()
                )
            )

            webpage_features, final_url, webpage_ok = (
                extract_webpage_features(
                    normalized_url
                )
            )

            all_features = {}

            all_features.update(
                url_features
            )

            all_features.update(
                webpage_features
            )

            # Make sure every model feature exists
            for column in feature_columns:

                if column not in all_features:

                    all_features[column] = 0

            prediction, confidence = (
                predict_forest(
                    all_features
                )
            )

        st.divider()

        if prediction == 0:

            st.error(
                "🚨 PHISHING WEBSITE DETECTED"
            )

            st.write(
                f"Model confidence: "
                f"**{confidence:.2%}**"
            )

            st.warning(
                "Avoid entering passwords, "
                "banking details, OTP codes, "
                "or other sensitive information."
            )

        else:

            st.success(
                "✅ LIKELY LEGITIMATE WEBSITE"
            )

            st.write(
                f"Model confidence: "
                f"**{confidence:.2%}**"
            )

        st.divider()

        st.subheader(
            "🔎 Security Analysis"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "HTTPS",
                "Yes"
                if all_features.get(
                    "IsHTTPS", 0
                )
                else "No"
            )

            st.metric(
                "Subdomains",
                all_features.get(
                    "NoOfSubDomain", 0
                )
            )

            st.metric(
                "External References",
                all_features.get(
                    "NoOfExternalRef", 0
                )
            )

        with col2:

            st.metric(
                "JavaScript Files",
                all_features.get(
                    "NoOfJS", 0
                )
            )

            st.metric(
                "Images",
                all_features.get(
                    "NoOfImage", 0
                )
            )

            st.metric(
                "Password Field",
                "Yes"
                if all_features.get(
                    "HasPasswordField", 0
                )
                else "No"
            )

        with st.expander(
            "📊 All Extracted Features"
        ):

            feature_df = pd.DataFrame(
                list(
                    all_features.items()
                ),
                columns=[
                    "Feature",
                    "Value"
                ]
            )

            st.dataframe(
                feature_df,
                use_container_width=True
            )

        st.caption(
            f"Analyzed domain: {domain}"
        )

        if not webpage_ok:

            st.info(
                "The website could not be fully "
                "retrieved. The prediction is based "
                "mainly on available URL features."
            )


st.divider()

st.caption(
    "PhishGuard AI | ML Cybersecurity Case Study"
)