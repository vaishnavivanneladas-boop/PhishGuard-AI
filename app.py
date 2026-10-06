import json
import ipaddress
import re
from html import escape
from pathlib import Path
from textwrap import dedent
from urllib.parse import parse_qsl, unquote, urlsplit

import joblib
import pandas as pd
import streamlit as st

from url_features import extract_url_features


SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "confirm",
    "confirmation",
    "payment",
    "billing",
    "wallet",
    "bank",
    "credential",
    "authenticate",
    "unlock",
    "recover",
)

MULTI_LABEL_PUBLIC_SUFFIXES = {
    "ac.uk",
    "co.in",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.sg",
    "com.tr",
    "co.za",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}


def inspect_url(clean_url):
    """Parse URL structure and create explanatory-only security indicators."""
    normalized_url = (
        clean_url
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url)
        else f"http://{clean_url}"
    )
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("The URL must contain a hostname.")

    try:
        port = parsed.port
    except ValueError:
        port = "Invalid"
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    labels = hostname.rstrip(".").split(".")
    suffix_length = (
        2
        if ".".join(labels[-2:]).lower() in MULTI_LABEL_PUBLIC_SUFFIXES
        else 1
    )
    if is_ip_address or len(labels) <= suffix_length:
        subdomain_labels = []
        registered_domain = hostname
        tld = ""
    else:
        subdomain_labels = labels[: -(suffix_length + 1)]
        registered_domain = ".".join(labels[-(suffix_length + 1) :])
        tld = f".{labels[-1]}"

    decoded_url = unquote(clean_url).lower()
    keyword_matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
            decoded_url,
        )
    ]
    authentication_keywords = {
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "confirm",
        "confirmation",
        "credential",
        "authenticate",
        "unlock",
        "recover",
    }
    query_parameters = parse_qsl(parsed.query, keep_blank_values=True)
    special_character_count = sum(not character.isalnum() for character in clean_url)
    special_character_ratio = special_character_count / max(len(clean_url), 1)
    suspicious_structure = bool(
        parsed.username
        or parsed.password
        or hostname.lower().startswith("xn--")
        or (
            len(subdomain_labels) >= 2
            and sum(label.count("-") for label in labels) >= 3
        )
        or (
            len([part for part in parsed.path.split("/") if part]) >= 5
            and bool(keyword_matches)
        )
    )

    indicators = []

    def add_indicator(condition, warning, success, category):
        indicators.append(
            {
                "level": "warning" if condition else "good",
                "text": warning if condition else success,
                "category": category if condition else None,
            }
        )

    protocol_warning = (
        "HTTP connection detected; traffic is not protected by HTTPS."
        if parsed.scheme.lower() == "http"
        else f"{parsed.scheme.upper()} protocol detected; HTTPS is not being used."
    )
    add_indicator(
        parsed.scheme.lower() != "https",
        protocol_warning,
        "HTTPS connection detected (this does not guarantee the site is safe).",
        "http",
    )
    add_indicator(
        is_ip_address,
        "An IP address is used as the hostname.",
        "No IP address detected in the hostname.",
        "ip",
    )
    add_indicator(
        len(clean_url) > 100,
        f"Long URL structure ({len(clean_url)} characters).",
        f"URL length is within the usual range ({len(clean_url)} characters).",
        "length",
    )
    add_indicator(
        len(subdomain_labels) > 3,
        f"Excessive subdomain depth ({len(subdomain_labels)} subdomains).",
        f"No excessive subdomain depth ({len(subdomain_labels)} subdomains).",
        "subdomains",
    )
    add_indicator(
        bool(keyword_matches),
        "URL contains suspicious keyword wording.",
        "No suspicious keywords detected.",
        "keywords",
    )
    add_indicator(
        "%" in clean_url,
        "Percent encoding / URL obfuscation is present.",
        "No percent-encoding indicator detected.",
        "obfuscation",
    )
    add_indicator(
        special_character_count >= 10 and special_character_ratio > 0.30,
        "URL contains a high proportion of special characters.",
        "Special-character usage is within the usual range.",
        "special_characters",
    )
    add_indicator(
        len(query_parameters) > 5,
        f"URL contains many query parameters ({len(query_parameters)}).",
        f"Query parameter count is not excessive ({len(query_parameters)}).",
        "query",
    )
    auth_matches = [
        keyword for keyword in keyword_matches if keyword in authentication_keywords
    ]
    add_indicator(
        bool(auth_matches),
        "Authentication-related wording detected: "
        + ", ".join(f'"{keyword}"' for keyword in auth_matches)
        + ".",
        "No authentication-related wording detected.",
        "authentication",
    )
    add_indicator(
        suspicious_structure,
        "URL has an unusual domain or path structure.",
        "No obvious unusual domain/path structure detected.",
        "structure",
    )

    intelligence = [
        ("Protocol", parsed.scheme.upper()),
        ("Domain", registered_domain or "None"),
        ("Subdomain", ".".join(subdomain_labels) or "None"),
        ("TLD", tld or "None"),
        ("Port", str(port) if port is not None else "Default"),
        ("URL Length", str(len(clean_url))),
        ("Domain Length", str(len(registered_domain))),
        ("Path", parsed.path or "/"),
        ("Query Parameters", str(len(query_parameters))),
        ("Fragment", parsed.fragment or "None"),
        ("IP Address", "Yes" if is_ip_address else "No"),
        ("Number of Subdomains", str(len(subdomain_labels))),
    ]
    structure = [
        ("Protocol", parsed.scheme.lower()),
        ("Hostname", hostname),
        ("Subdomain", ".".join(subdomain_labels) or "None"),
        ("Registered domain", registered_domain or "None"),
        ("TLD", tld or "None"),
        ("Port", str(port) if port is not None else "Default"),
        ("Path", parsed.path or "/"),
        ("Query", parsed.query or "None"),
        ("Fragment", parsed.fragment or "None"),
    ]
    return {
        "intelligence": intelligence,
        "structure": structure,
        "indicators": indicators,
        "keywords": keyword_matches,
        "is_https": parsed.scheme.lower() == "https",
        "is_ip_address": is_ip_address,
        "is_obfuscated": "%" in clean_url,
        "is_long": len(clean_url) > 100,
        "subdomain_count": len(subdomain_labels),
    }


def render_detail_grid(items):
    """Render labeled URL details as escaped HTML cards."""
    rows = "".join(
        (
            '<div class="detail-item">'
            f'<div class="detail-label">{escape(str(label))}</div>'
            f'<div class="detail-value">{escape(str(value))}</div>'
            "</div>"
        )
        for label, value in items
    )
    render_html(f'<div class="detail-grid">{rows}</div>')


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

MODEL_PATH = PROJECT_ROOT / "models" / "phishguard_url_model.joblib"
FEATURE_PATH = PROJECT_ROOT / "models" / "url_feature_columns.json"


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# HTML HELPER
# ============================================================

def render_html(html):
    """Render custom HTML directly rather than passing it through Markdown."""
    st.html(dedent(html))


# ============================================================
# CUSTOM CSS
# ============================================================

st.html(
    """
    <style>

    /* ========================================================
       GLOBAL
       ======================================================== */

    .stApp {
        background:
            radial-gradient(
                circle at 10% 10%,
                rgba(30, 64, 175, 0.18),
                transparent 28%
            ),
            radial-gradient(
                circle at 90% 20%,
                rgba(6, 182, 212, 0.10),
                transparent 25%
            ),
            #070b14;

        color: #e5e7eb;
    }

    .main .block-container {
        max-width: 1250px;
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }


    /* ========================================================
       SIDEBAR
       ======================================================== */

    [data-testid="stSidebar"] {
        background: #0b1120;
        border-right: 1px solid rgba(148, 163, 184, 0.12);
    }

    [data-testid="stSidebar"] * {
        color: #dbeafe;
    }


    /* ========================================================
       BRAND
       ======================================================== */

    .brand {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 5px;
    }

    .brand-icon {
        width: 52px;
        height: 52px;
        border-radius: 15px;

        background: linear-gradient(
            135deg,
            #2563eb,
            #06b6d4
        );

        display: flex;
        align-items: center;
        justify-content: center;

        font-size: 27px;

        box-shadow:
            0 10px 30px
            rgba(37, 99, 235, 0.25);
    }

    .brand-name {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: -0.8px;
        color: #f8fafc;
    }

    .brand-ai {
        color: #38bdf8;
    }

    .subtitle {
        color: #94a3b8;
        font-size: 14px;
        margin-left: 67px;
        margin-top: -8px;
    }


    /* ========================================================
       STATUS
       ======================================================== */

    .status {
        display: inline-flex;
        align-items: center;
        gap: 7px;

        background: rgba(34, 197, 94, 0.08);
        border: 1px solid rgba(34, 197, 94, 0.20);

        color: #86efac;

        padding: 7px 13px;
        border-radius: 999px;

        font-size: 12px;
        font-weight: 600;
    }

    .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;

        background: #22c55e;

        box-shadow:
            0 0 10px #22c55e;
    }


    /* ========================================================
       HERO
       ======================================================== */

    .hero {
        text-align: center;
        padding: 45px 20px 30px 20px;
    }

    .hero-title {
        font-size: 46px;
        font-weight: 800;
        letter-spacing: -1.8px;
        line-height: 1.12;

        color: #f8fafc;

        margin-bottom: 14px;
    }

    .hero-gradient {
        background: linear-gradient(
            90deg,
            #60a5fa,
            #22d3ee
        );

        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .hero-text {
        max-width: 650px;
        margin: auto;

        color: #94a3b8;

        font-size: 16px;
        line-height: 1.7;
    }


    /* ========================================================
       SCANNER
       ======================================================== */

    .scan-card {
        background: rgba(15, 23, 42, 0.72);

        border: 1px solid
            rgba(96, 165, 250, 0.15);

        border-radius: 22px;

        padding: 28px;

        box-shadow:
            0 20px 60px
            rgba(0, 0, 0, 0.25);

        backdrop-filter: blur(15px);
    }

    .scan-label {
        font-size: 15px;
        font-weight: 700;

        color: #e2e8f0;

        margin-bottom: 8px;
    }


    /* ========================================================
       INPUT
       ======================================================== */

    .stTextInput > div > div > input {
        background: #111827 !important;

        color: #f8fafc !important;

        border: 1px solid #334155 !important;

        border-radius: 12px !important;

        padding: 14px !important;

        font-size: 15px !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: #38bdf8 !important;

        box-shadow:
            0 0 0 1px #38bdf8 !important;
    }


    /* ========================================================
       BUTTON
       ======================================================== */

    .stButton > button {
        width: 100%;

        border-radius: 12px;

        border: none;

        padding: 13px 20px;

        font-weight: 700;

        font-size: 15px;

        color: white;

        background: linear-gradient(
            90deg,
            #2563eb,
            #0891b2
        );

        transition: all 0.2s ease;

        box-shadow:
            0 8px 25px
            rgba(37, 99, 235, 0.20);
    }

    .stButton > button:hover {
        transform: translateY(-1px);

        box-shadow:
            0 12px 30px
            rgba(37, 99, 235, 0.35);
    }


    /* ========================================================
       SECTION TITLES
       ======================================================== */

    .section-title {
        font-size: 21px;
        font-weight: 750;

        color: #f8fafc;

        margin-top: 28px;
        margin-bottom: 15px;
    }


    /* ========================================================
       RESULT CARDS
       ======================================================== */

    .result-card {
        background: #0f172a;

        border: 1px solid #1e293b;

        border-radius: 18px;

        padding: 22px;

        min-height: 125px;

        box-shadow:
            0 10px 30px
            rgba(0, 0, 0, 0.15);
    }

    .result-label {
        color: #94a3b8;

        font-size: 13px;

        margin-bottom: 8px;
    }

    .result-value {
        font-size: 29px;

        font-weight: 800;

        color: #f8fafc;
    }

    .result-small {
        color: #64748b;

        font-size: 12px;

        margin-top: 6px;
    }


    /* ========================================================
       SAFE RESULT
       ======================================================== */

    .safe-result {
        background: linear-gradient(
            135deg,
            rgba(22, 163, 74, 0.12),
            rgba(15, 23, 42, 0.95)
        );

        border: 1px solid
            rgba(34, 197, 94, 0.28);

        border-radius: 18px;

        padding: 22px;

        margin-top: 20px;
    }

    .safe-title {
        color: #4ade80;

        font-size: 21px;

        font-weight: 800;

        margin-bottom: 6px;
    }

    .safe-text {
        color: #a7f3d0;

        line-height: 1.6;
    }


    /* ========================================================
       DANGER RESULT
       ======================================================== */

    .danger-result {
        background: linear-gradient(
            135deg,
            rgba(220, 38, 38, 0.13),
            rgba(15, 23, 42, 0.95)
        );

        border: 1px solid
            rgba(248, 113, 113, 0.28);

        border-radius: 18px;

        padding: 22px;

        margin-top: 20px;
    }

    .danger-title {
        color: #f87171;

        font-size: 21px;

        font-weight: 800;

        margin-bottom: 6px;
    }

    .danger-text {
        color: #fecaca;

        line-height: 1.6;
    }


    /* ========================================================
       METRIC CARDS
       ======================================================== */

    .metric-card {
        background: #0f172a;

        border: 1px solid #1e293b;

        border-radius: 16px;

        padding: 20px;

        text-align: center;

        min-height: 100px;
    }

    .metric-number {
        font-size: 27px;

        font-weight: 800;

        color: #38bdf8;
    }

    .metric-name {
        font-size: 12px;

        color: #94a3b8;

        margin-top: 6px;

        letter-spacing: 0.5px;
    }


    /* ========================================================
       FOOTER
       ======================================================== */

    .footer {
        text-align: center;

        color: #64748b;

        font-size: 12px;

        padding-top: 35px;

        padding-bottom: 10px;
    }


    /* ========================================================
       EXPANDER
       ======================================================== */

    .streamlit-expanderHeader {
        background: #0f172a !important;

        border-radius: 12px !important;

        color: #cbd5e1 !important;
    }


    /* ========================================================
       DATAFRAME
       ======================================================== */

    [data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }

    .detail-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 10px;
        margin: 8px 0 14px;
    }

    .detail-item {
        min-width: 0;
        padding: 13px 15px;
        border-radius: 13px;
        background: rgba(15, 23, 42, 0.78);
        border: 1px solid rgba(96, 165, 250, 0.14);
    }

    .detail-label {
        margin-bottom: 6px;
        color: #94a3b8;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.07em;
        text-transform: uppercase;
    }

    .detail-value {
        overflow-wrap: anywhere;
        color: #e2e8f0;
        font-size: 14px;
        font-weight: 600;
    }

    .risk-summary {
        margin: 16px 0;
        padding: 24px;
        border: 1px solid rgba(96, 165, 250, 0.2);
        border-radius: 20px;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(8, 47, 73, 0.62));
        text-align: center;
    }

    .risk-summary.low { border-color: rgba(34, 197, 94, 0.35); }
    .risk-summary.medium { border-color: rgba(250, 204, 21, 0.38); }
    .risk-summary.high { border-color: rgba(248, 113, 113, 0.38); }

    .risk-summary-level {
        font-size: 22px;
        font-weight: 800;
        letter-spacing: 0.08em;
    }

    .risk-summary.low .risk-summary-level { color: #4ade80; }
    .risk-summary.medium .risk-summary-level { color: #facc15; }
    .risk-summary.high .risk-summary-level { color: #f87171; }

    .risk-summary-score {
        margin-top: 8px;
        color: #f8fafc;
        font-size: 34px;
        font-weight: 800;
    }

    .risk-summary-caption {
        margin-top: 2px;
        color: #94a3b8;
        font-size: 12px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    .risk-meter {
        margin: 12px 0 4px;
        padding: 17px 19px;
        border-radius: 16px;
        background: rgba(15, 23, 42, 0.82);
        border: 1px solid rgba(96, 165, 250, 0.14);
    }

    .risk-meter-labels {
        display: flex;
        justify-content: space-between;
        margin-bottom: 8px;
        color: #94a3b8;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.06em;
    }

    .risk-meter-track {
        height: 12px;
        overflow: hidden;
        border-radius: 999px;
        background: linear-gradient(90deg, #22c55e 0%, #facc15 50%, #ef4444 100%);
    }

    .risk-meter-fill {
        height: 100%;
        margin-left: auto;
        border-radius: 999px 0 0 999px;
        background: rgba(7, 11, 20, 0.88);
    }

    .risk-meter-value {
        margin-top: 8px;
        color: #e2e8f0;
        font-size: 13px;
        font-weight: 700;
        text-align: right;
    }

    .indicator-list, .reason-list, .keyword-list {
        display: grid;
        gap: 8px;
        margin: 8px 0;
    }

    .indicator-row, .reason-row, .keyword-chip {
        padding: 11px 14px;
        border-radius: 12px;
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.12);
        color: #cbd5e1;
        line-height: 1.5;
    }

    .indicator-row.warning {
        border-color: rgba(250, 204, 21, 0.24);
        color: #fde68a;
    }

    .indicator-row.good {
        border-color: rgba(34, 197, 94, 0.2);
        color: #bbf7d0;
    }

    .keyword-chip {
        display: inline-block;
        margin: 0 7px 7px 0;
        border-color: rgba(248, 113, 113, 0.25);
        color: #fca5a5;
        font-weight: 700;
    }

    .analysis-note {
        margin: 8px 0;
        color: #94a3b8;
        font-size: 13px;
        line-height: 1.6;
    }

    </style>
    """
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    model = joblib.load(MODEL_PATH)

    with open(FEATURE_PATH, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return model, feature_columns


try:

    model, feature_columns = load_model()

except Exception as e:

    st.error("Unable to load PhishGuard AI model.")

    st.code(str(e))

    st.stop()


# ============================================================
# SESSION STATE
# ============================================================

if "scan_history" not in st.session_state:

    st.session_state.scan_history = []


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    render_html(
        """
        <div class="brand">
            <div class="brand-icon">🛡️</div>

            <div class="brand-name">
                PhishGuard<span class="brand-ai"> AI</span>
            </div>
        </div>

        <div class="subtitle">
            Next-Generation URL Security
        </div>
        """
    )

    st.html("<br>")

    render_html(
        """
        <div class="status">
            <span class="status-dot"></span>
            MODEL ONLINE
        </div>
        """
    )

    st.markdown("---")

    st.markdown("### 🧠 Model")

    st.caption("Random Forest Classifier")

    st.markdown("### 📊 Performance")

    st.metric("Accuracy", "99.51%")

    st.metric("F1 Score", "99.57%")

    st.markdown("---")

    st.markdown("### 🔬 Detection")

    st.write("19 URL-only features")

    st.write("Domain-grouped validation")

    st.write("235,795 training URLs")

    st.markdown("---")

    st.caption(
        "PhishGuard AI is a machine-learning "
        "based URL risk assessment system."
    )


# ============================================================
# TOP HEADER
# ============================================================

header_col1, header_col2 = st.columns([5, 1])

with header_col1:

    render_html(
        """
        <div class="brand">
            <div class="brand-icon">🛡️</div>

            <div class="brand-name">
                PhishGuard<span class="brand-ai"> AI</span>
            </div>
        </div>

        <div class="subtitle">
            Machine Learning Based Phishing URL Detection
        </div>
        """
    )


with header_col2:

    render_html(
        """
        <div class="status">
            <span class="status-dot"></span>
            SYSTEM READY
        </div>
        """
    )


# ============================================================
# HERO
# ============================================================

render_html(
    """
    <div class="hero">

        <div class="hero-title">
            Detect
            <span class="hero-gradient"> Phishing</span>
            <br>
            Before It Tricks You
        </div>

        <div class="hero-text">
            Analyze suspicious URLs using machine learning
            and 19 structural URL features to estimate
            phishing risk in real time.
        </div>

    </div>
    """
)


# ============================================================
# URL SCANNER
# ============================================================

render_html(
    """
    <div class="scan-card">

        <div class="scan-label">
            🔗 Enter a URL to analyze
        </div>

    </div>
    """
)

url = st.text_input(
    "URL",
    placeholder="https://example.com",
    label_visibility="collapsed"
)

scan = st.button(
    "🔍  ANALYZE URL"
)


# ============================================================
# ANALYSIS
# ============================================================

if scan:

    if not url.strip():

        st.warning(
            "Please enter a URL before starting the analysis."
        )

        st.stop()

    with st.spinner(
        "Analyzing URL security characteristics..."
    ):

        try:

            clean_url = url.strip()

            # ------------------------------------------------
            # Extract exact training/deployment features
            # ------------------------------------------------

            features = extract_url_features(clean_url)

            # ------------------------------------------------
            # Prepare model input
            # ------------------------------------------------

            X_input = pd.DataFrame(
                [
                    [
                        features[col]
                        for col in feature_columns
                    ]
                ],
                columns=feature_columns
            )

            # ------------------------------------------------
            # Prediction
            # ------------------------------------------------

            prediction = model.predict(X_input)[0]

            probabilities = model.predict_proba(
                X_input
            )[0]

            probability_map = dict(
                zip(
                    model.classes_,
                    probabilities
                )
            )

            phishing_probability = (
                probability_map.get(0, 0.0)
            )

            legitimate_probability = (
                probability_map.get(1, 0.0)
            )

            # Explanatory URL parsing and rules are UI-only; model input is unchanged.
            url_analysis = inspect_url(clean_url)

            # ------------------------------------------------
            # Store history
            # ------------------------------------------------

            st.session_state.scan_history.insert(
                0,
                {
                    "url": clean_url,

                    "prediction": (
                        "PHISHING"
                        if prediction == 0
                        else "LEGITIMATE"
                    ),

                    "phishing": phishing_probability
                }
            )

            st.session_state.scan_history = (
                st.session_state.scan_history[:5]
            )

        except Exception as e:

            st.error(
                "Unable to analyze this URL."
            )

            st.code(str(e))

            st.stop()


    # ========================================================
    # SECURITY ANALYSIS
    # ========================================================

    render_html(
        """
        <div class="section-title">
            📊 Security Analysis
        </div>
        """
    )

    col1, col2, col3 = st.columns(3)


    # --------------------------------------------------------
    # Risk Level
    # --------------------------------------------------------

    if phishing_probability <= 0.30:
        risk_level = "LOW RISK"
        risk_class = "low"
        risk_icon = "🟢"
    elif phishing_probability <= 0.70:
        risk_level = "MEDIUM RISK"
        risk_class = "medium"
        risk_icon = "⚠️"
    else:
        risk_level = "HIGH RISK"
        risk_class = "high"
        risk_icon = "🚨"


    with col1:

        render_html(
            f"""
            <div class="result-card">

                <div class="result-label">
                    RISK LEVEL
                </div>

                <div class="result-value">
                    {risk_icon} {risk_level}
                </div>

                <div class="result-small">
                    Machine learning assessment
                </div>

            </div>
            """
        )


    # --------------------------------------------------------
    # Phishing Probability
    # --------------------------------------------------------

    with col2:

        render_html(
            f"""
            <div class="result-card">

                <div class="result-label">
                    PHISHING PROBABILITY
                </div>

                <div class="result-value">
                    {phishing_probability * 100:.2f}%
                </div>

                <div class="result-small">
                    Model probability for phishing
                </div>

            </div>
            """
        )


    # --------------------------------------------------------
    # Legitimate Probability
    # --------------------------------------------------------

    with col3:

        render_html(
            f"""
            <div class="result-card">

                <div class="result-label">
                    LEGITIMATE PROBABILITY
                </div>

                <div class="result-value">
                    {legitimate_probability * 100:.2f}%
                </div>

                <div class="result-small">
                    Model probability for legitimate
                </div>

            </div>
            """
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    if prediction == 0:

        render_html(
            """
            <div class="danger-result">

                <div class="danger-title">
                    🚨 PHISHING URL DETECTED
                </div>

                <div class="danger-text">
                    The model identified characteristics
                    associated with phishing URLs.
                    Avoid entering passwords, OTPs,
                    banking information, or other
                    sensitive data.
                </div>

            </div>
            """
        )

    else:

        render_html(
            """
            <div class="safe-result">

                <div class="safe-title">
                    ✅ URL CLASSIFIED AS LEGITIMATE
                </div>

                <div class="safe-text">
                    The URL appears legitimate according
                    to the machine-learning model.
                    However, this result does not guarantee
                    that the website is completely safe.
                </div>

            </div>
            """
        )


    render_html(
        f"""
        <div class="risk-summary {risk_class}">
            <div class="risk-summary-level">{risk_icon} {risk_level}</div>
            <div class="risk-summary-score">{phishing_probability * 100:.2f}%</div>
            <div class="risk-summary-caption">Phishing Probability</div>
        </div>
        """
    )

    # ========================================================
    # PROBABILITY DISTRIBUTION AND RISK METER
    # ========================================================

    render_html(
        """
        <div class="section-title">
            📈 Probability Distribution &amp; Risk Meter
        </div>
        """
    )

    gauge_percentage = min(max(float(phishing_probability) * 100, 0.0), 100.0)
    render_html(
        f"""
        <div class="risk-meter">
            <div class="risk-meter-labels">
                <span>LOW</span><span>MEDIUM</span><span>HIGH</span>
            </div>
            <div class="risk-meter-track">
                <div class="risk-meter-fill" style="width: {100 - gauge_percentage:.2f}%"></div>
            </div>
            <div class="risk-meter-value">{gauge_percentage:.2f}% phishing probability</div>
        </div>
        """
    )

    st.progress(
        float(phishing_probability),
        text=(
            f"Phishing Risk — "
            f"{phishing_probability * 100:.2f}%"
        )
    )

    st.progress(
        float(legitimate_probability),
        text=(
            f"Legitimate — "
            f"{legitimate_probability * 100:.2f}%"
        )
    )

    # ========================================================
    # EXPLAINABLE URL ANALYSIS
    # ========================================================

    if prediction == 0:
        reason_heading = "🧠 Why Was This URL Flagged?"
        if phishing_probability >= 0.70:
            reasons = ["The machine-learning model assigned a high phishing probability."]
        else:
            reasons = ["The machine-learning model classified this URL as phishing."]
        if url_analysis["keywords"]:
            reasons.append(
                "Authentication-related or suspicious wording appears in the URL: "
                + ", ".join(url_analysis["keywords"])
                + "."
            )
        if not url_analysis["is_https"]:
            reasons.append("The URL uses HTTP instead of HTTPS.")
        if url_analysis["is_ip_address"]:
            reasons.append("The hostname is an IP address.")
        if url_analysis["is_long"] or url_analysis["subdomain_count"] > 3:
            reasons.append("The URL has a long or deeply nested structure.")
        if url_analysis["is_obfuscated"]:
            reasons.append("Percent-encoded characters are present in the URL.")
        if any(
            item["category"] == "special_characters"
            for item in url_analysis["indicators"]
        ):
            reasons.append("The URL contains an unusually high proportion of special characters.")
        if any(item["category"] == "query" for item in url_analysis["indicators"]):
            reasons.append("The URL contains an unusually high number of query parameters.")
        if any(item["category"] == "structure" for item in url_analysis["indicators"]):
            reasons.append("The domain or path has an unusual structure.")
    else:
        reason_heading = (
            "🟢 Why Was This URL Classified as Lower Risk?"
            if risk_level == "LOW RISK"
            else "🟢 Why Did the Model Classify This URL as Legitimate?"
        )
        reasons = []
        if phishing_probability < 0.30:
            reasons.append("The machine-learning model assigned a low phishing probability.")
        else:
            reasons.append(
                "The model's top prediction is legitimate, although the probability-based "
                f"risk band is {risk_level.lower()}."
            )
        if url_analysis["is_https"]:
            reasons.append("HTTPS is being used; this does not guarantee the site is safe.")
        if not url_analysis["is_ip_address"]:
            reasons.append("No IP address was detected as the hostname.")
        if not url_analysis["keywords"]:
            reasons.append("No suspicious authentication keywords were detected.")
        if (
            not url_analysis["is_long"]
            and url_analysis["subdomain_count"] <= 3
            and not url_analysis["is_obfuscated"]
            and not any(item["category"] == "structure" for item in url_analysis["indicators"])
        ):
            reasons.append("The URL structure appears relatively ordinary.")

    with st.expander(reason_heading, expanded=True):
        reason_rows = "".join(
            f'<div class="reason-row">{escape(reason)}</div>'
            for reason in reasons
        )
        render_html(f'<div class="reason-list">{reason_rows}</div>')
        st.caption(
            "Rule-based indicators explain URL characteristics only. They do not "
            "change the Random Forest prediction, and no single indicator proves maliciousness."
        )

    with st.expander("🔍 URL Intelligence"):
        render_detail_grid(url_analysis["intelligence"])

    with st.expander("🧩 URL Structure"):
        render_detail_grid(url_analysis["structure"])

    with st.expander("🚨 Security Indicators"):
        indicator_rows = "".join(
            (
                f'<div class="indicator-row {item["level"]}">'
                f'{"⚠️" if item["level"] == "warning" else "✅"} '
                f'{escape(item["text"])}'
                "</div>"
            )
            for item in url_analysis["indicators"]
        )
        render_html(f'<div class="indicator-list">{indicator_rows}</div>')

    with st.expander("🔑 Suspicious Keywords"):
        if url_analysis["keywords"]:
            keyword_html = "".join(
                f'<span class="keyword-chip">🔴 {escape(keyword)}</span>'
                for keyword in url_analysis["keywords"]
            )
            render_html(f'<div class="keyword-list">{keyword_html}</div>')
            st.caption(
                "Authentication-related wording was detected in the URL. "
                "Keyword presence alone does not prove that a URL is phishing."
            )
        else:
            st.success("✅ No suspicious keywords detected.")

    render_html('<div class="section-title">🛡️ Security Summary</div>')
    summary_columns = st.columns(4)
    summary_values = [
        ("ML Detection", "Phishing" if prediction == 0 else "Legitimate"),
        ("Risk Level", risk_level),
        ("HTTPS", "Yes" if url_analysis["is_https"] else "No"),
        ("IP Address", "Yes" if url_analysis["is_ip_address"] else "No"),
        ("Suspicious Keywords", "Detected" if url_analysis["keywords"] else "None"),
        ("URL Obfuscation", "Detected" if url_analysis["is_obfuscated"] else "None"),
        ("URL Length", "Long" if url_analysis["is_long"] else "Normal"),
        ("Subdomains", str(url_analysis["subdomain_count"])),
    ]
    for index, (label, value) in enumerate(summary_values):
        with summary_columns[index % len(summary_columns)]:
            render_html(
                f"""
                <div class="detail-item">
                    <div class="detail-label">{escape(label)}</div>
                    <div class="detail-value">{escape(value)}</div>
                </div>
                """
            )

    # ========================================================
    # URL FEATURES
    # ========================================================

    with st.expander(
        "🔬 View Extracted URL Features"
    ):

        feature_table = pd.DataFrame(
            {
                "Feature": feature_columns,

                "Value": [
                    features[col]
                    for col in feature_columns
                ]
            }
        )

        st.dataframe(
            feature_table,
            width="stretch",
            hide_index=True
        )


# ============================================================
# RECENT SCANS
# ============================================================

if st.session_state.scan_history:

    render_html(
        """
        <div class="section-title">
            🕘 Recent Scans
        </div>
        """
    )

    history_df = pd.DataFrame(
        st.session_state.scan_history
    )

    history_df["phishing"] = (
        history_df["phishing"] * 100
    ).round(2)

    history_df.columns = [
        "URL",
        "Prediction",
        "Phishing Probability (%)"
    ]

    st.dataframe(
        history_df,
        width="stretch",
        hide_index=True
    )


# ============================================================
# MODEL PERFORMANCE
# ============================================================

render_html(
    """
    <div class="section-title">
        🏆 Model Performance
    </div>
    """
)

m1, m2, m3, m4 = st.columns(4)


with m1:

    render_html(
        """
        <div class="metric-card">

            <div class="metric-number">
                99.51%
            </div>

            <div class="metric-name">
                ACCURACY
            </div>

        </div>
        """
    )


with m2:

    render_html(
        """
        <div class="metric-card">

            <div class="metric-number">
                99.58%
            </div>

            <div class="metric-name">
                PRECISION
            </div>

        </div>
        """
    )


with m3:

    render_html(
        """
        <div class="metric-card">

            <div class="metric-number">
                99.57%
            </div>

            <div class="metric-name">
                RECALL
            </div>

        </div>
        """
    )


with m4:

    render_html(
        """
        <div class="metric-card">

            <div class="metric-number">
                99.57%
            </div>

            <div class="metric-name">
                F1 SCORE
            </div>

        </div>
        """
    )


# ============================================================
# FOOTER
# ============================================================

render_html(
    """
    <div class="footer">

        🛡️ PhishGuard AI
        &nbsp;•&nbsp;
        Machine Learning Based Phishing URL Detection

        <br><br>

        Built with Python • Scikit-learn • Streamlit

    </div>
    """
)