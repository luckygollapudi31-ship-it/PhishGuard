
import re
import csv
from io import BytesIO, StringIO
from datetime import datetime
from xml.sax.saxutils import escape

import streamlit as st
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)


# =====================================================
# PHISHGUARD - PROFESSIONAL EMAIL SECURITY ANALYSIS
# =====================================================

st.set_page_config(
    page_title="PhishGuard | Cybersecurity",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #061326, #0B1D35);
    color: #EAF4FF;
}

[data-testid="stHeader"] {
    background: transparent;
}

[data-testid="stSidebar"] {
    background: #0A192C;
    border-right: 1px solid #24415F;
}

.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

h1, h2, h3, h4, p, label {
    color: #EAF4FF !important;
}

.pg-header {
    background: linear-gradient(120deg, #10243D, #15375B);
    border: 1px solid #315477;
    border-radius: 18px;
    padding: 30px;
    margin-bottom: 25px;
}

.pg-subtitle {
    color: #A9C1DC !important;
    font-size: 15px;
}

.pg-card {
    background: #10243D;
    border: 1px solid #24415F;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 15px;
}

.pg-small {
    color: #8CBCEB;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.5px;
}

.pg-footer {
    text-align: center;
    color: #9DB6D2;
    padding: 30px 0;
    font-size: 13px;
}

[data-testid="stMetric"] {
    background: #10243D;
    border: 1px solid #315477;
    border-radius: 13px;
    padding: 18px;
}

[data-testid="stMetricValue"] {
    color: #38BDF8;
}

.stTextArea textarea,
.stTextInput input {
    background-color: #0B1D35 !important;
    color: #FFFFFF !important;
    border: 1px solid #315477 !important;
    border-radius: 10px !important;
}

.stButton > button,
.stDownloadButton > button {
    background: linear-gradient(90deg, #0878D1, #2563EB);
    color: white !important;
    border: none;
    border-radius: 9px;
    font-weight: 700;
    min-height: 44px;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: #168CEB;
    color: white !important;
    border: 1px solid #38BDF8;
}

div[data-testid="stAlert"] {
    border-radius: 10px;
}

div[data-testid="stAlert"] p,
div[data-testid="stAlert"] span {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

.stTabs [data-baseweb="tab"] {
    color: #DCEBFA;
    font-weight: 600;
}

.stTabs [aria-selected="true"] {
    color: #38BDF8 !important;
}

hr {
    border-color: #24415F;
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# SESSION STATE
# =====================================================

if "history" not in st.session_state:
    st.session_state.history = []

if "email_result" not in st.session_state:
    st.session_state.email_result = None

if "url_result" not in st.session_state:
    st.session_state.url_result = None


# =====================================================
# DETECTION RULES
# =====================================================

SUSPICIOUS_KEYWORDS = [
    "winner",
    "congratulations",
    "claim now",
    "free prize",
    "urgent",
    "immediately",
    "account blocked",
    "verify your account",
    "password",
    "bank details",
    "click here"
]


def extract_urls(text):
    """Extract website links from text."""

    found = re.findall(
        r'https?://[^\s<>]+|www\.[^\s<>]+',
        text.lower()
    )

    return list(dict.fromkeys(
        url.rstrip(".,!?;:)]}") for url in found
    ))


def check_url(url):
    """Check a URL against simple suspicious patterns."""

    url = url.strip().lower()

    reasons = []

    if url.startswith("http://"):
        reasons.append("Uses unencrypted HTTP")

    if any(shortener in url for shortener in [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"
    ]):
        reasons.append("Uses a URL shortening service")

    if re.search(
        r'https?://(?:\d{1,3}\.){3}\d{1,3}',
        url
    ):
        reasons.append("Contains an IP address instead of a domain name")

    if "@" in url:
        reasons.append("Contains an unusual @ symbol")

    if not reasons:
        reasons.append("No suspicious patterns from the current rule list were found")

    return reasons


def analyse_email(email):
    """Analyse email content and calculate its risk score."""

    email_lower = email.lower()

    detected_words = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in email_lower
    ]

    urls = extract_urls(email)

    suspicious_urls = []
    url_reasons = {}

    for url in urls:
        reasons = check_url(url)

        if any(
            reason != "No suspicious patterns from the current rule list were found"
            for reason in reasons
        ):
            suspicious_urls.append(url)
            url_reasons[url] = reasons

    keyword_points = min(len(detected_words) * 10, 60)
    url_points = min(len(suspicious_urls) * 25, 50)

    score = min(keyword_points + url_points, 100)

    if score >= 45:
        classification = "HIGH RISK"
    elif score >= 15:
        classification = "MEDIUM RISK"
    else:
        classification = "LOW RISK"

    return {
        "score": score,
        "classification": classification,
        "keywords": detected_words,
        "urls": urls,
        "suspicious_urls": suspicious_urls,
        "url_reasons": url_reasons,
        "keyword_points": keyword_points,
        "url_points": url_points,
        "email": email,
        "date": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }


def analyse_single_url(url):
    """Analyse one URL using the same pattern rules."""

    reasons = check_url(url)

    suspicious = any(
        reason != "No suspicious patterns from the current rule list were found"
        for reason in reasons
    )

    return {
        "url": url,
        "reasons": reasons,
        "suspicious": suspicious
    }


# =====================================================
# PDF REPORT
# =====================================================

def generate_pdf(result):

    buffer = BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "PGTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#12345A"),
        fontSize=23,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "PGHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0878D1"),
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "PGBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=15,
        spaceAfter=7
    )

    story = []

    story.append(Paragraph("PHISHGUARD", title_style))
    story.append(Paragraph(
        "Email Security Analysis Report",
        heading_style
    ))

    story.append(Paragraph(
        f"<b>Generated:</b> {escape(result['date'])}",
        body_style
    ))

    story.append(Spacer(1, 12))

    summary_data = [
        ["Risk Score", "Classification"],
        [
            f"{result['score']}/100",
            result["classification"]
        ],
        ["Keywords Found", "URLs Detected"],
        [
            str(len(result["keywords"])),
            str(len(result["urls"]))
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[230, 230]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12345A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#EAF4FF")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#10243D")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 9)
    ]))

    story.append(summary_table)

    story.append(Paragraph("Risk Score Breakdown", heading_style))

    story.append(Paragraph(
        f"Keyword points: {result['keyword_points']}",
        body_style
    ))

    story.append(Paragraph(
        f"Suspicious URL points: {result['url_points']}",
        body_style
    ))

    story.append(Paragraph("Suspicious Keywords", heading_style))

    if result["keywords"]:
        for word in result["keywords"]:
            story.append(Paragraph(
                f"• {escape(word)}",
                body_style
            ))
    else:
        story.append(Paragraph(
            "No listed suspicious keywords detected.",
            body_style
        ))

    story.append(Paragraph("Website Link Analysis", heading_style))

    if result["urls"]:
        for url in result["urls"]:
            story.append(Paragraph(
                escape(url),
                body_style
            ))

            if url in result["url_reasons"]:
                for reason in result["url_reasons"][url]:
                    story.append(Paragraph(
                        f" - {escape(reason)}",
                        body_style
                    ))
    else:
        story.append(Paragraph(
            "No website links detected.",
            body_style
        ))

    story.append(Paragraph(
        "Security Recommendations",
        heading_style
    ))

    recommendations = [
        "Do not click unknown or unexpected links.",
        "Never share passwords or banking details through email.",
        "Verify the sender using an independent contact method.",
        "Report suspected phishing emails to your organisation."
    ]

    for item in recommendations:
        story.append(Paragraph(
            f"• {escape(item)}",
            body_style
        ))

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "<b>Disclaimer:</b> PhishGuard is an educational prototype "
        "using keyword and URL pattern matching. It does not verify "
        "sender identity, visit URLs, or guarantee that an email is safe.",
        body_style
    ))

    pdf.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# =====================================================
# SIDEBAR
# =====================================================

with st.sidebar:

    st.markdown("## 🛡️ PhishGuard")

    st.caption("EMAIL THREAT ANALYSIS SYSTEM")

    st.divider()

    st.markdown("### System Status")

    st.success("System Online")

    st.markdown("### Detection Modules")

    st.markdown("""
    - Email keyword detection
    - URL pattern analysis
    - Risk score calculation
    - Threat classification
    - Security recommendations
    """)

    st.divider()

    st.markdown("### Project Information")

    st.write("**Developer:** Gollapudi Keziya")
    st.write("**Domain:** Cybersecurity")
    st.write("**Organisation:** LaunchED Global")

    st.divider()

    st.caption("PhishGuard | Version 2.0")


# =====================================================
# MAIN HEADER
# =====================================================

st.markdown("""
<div class="pg-header">
    <div style="display:flex; align-items:center; gap:15px;">
        <div style="font-size:48px;">🛡️</div>
        <div>
            <h1 style="margin:0;">PhishGuard</h1>
            <div class="pg-small">
                ADVANCED EMAIL THREAT ANALYSIS SYSTEM
            </div>
        </div>
        <div style="margin-left:auto; color:#4ADE80; font-weight:bold;">
            ● SYSTEM ONLINE
        </div>
    </div>
    <hr style="border-color:#315477;">
    <h2>Protect your inbox from phishing attacks.</h2>
    <p class="pg-subtitle">
        Analyse suspicious emails, inspect website links,
        identify phishing indicators and understand potential risks.
    </p>
</div>
""", unsafe_allow_html=True)


# =====================================================
# DASHBOARD METRICS
# =====================================================

total_scans = len(st.session_state.history)

high_risk_scans = sum(
    1 for item in st.session_state.history
    if item["Classification"] == "HIGH RISK"
)

medium_risk_scans = sum(
    1 for item in st.session_state.history
    if item["Classification"] == "MEDIUM RISK"
)

low_risk_scans = sum(
    1 for item in st.session_state.history
    if item["Classification"] == "LOW RISK"
)

st.markdown("### 📊 Security Dashboard")

m1, m2, m3, m4 = st.columns(4)

m1.metric("Total Scans", total_scans)
m2.metric("High Risk", high_risk_scans)
m3.metric("Medium Risk", medium_risk_scans)
m4.metric("Low Risk", low_risk_scans)

st.divider()


# =====================================================
# APPLICATION TABS
# =====================================================

tab1, tab2, tab3, tab4 = st.tabs([
    "📧 Email Scanner",
    "🔗 URL Checker",
    "📜 Scan History",
    "ℹ️ About PhishGuard"
])


# =====================================================
# TAB 1 - EMAIL SCANNER
# =====================================================

with tab1:

    st.markdown("## 🔍 Email Threat Scanner")

    st.markdown(
        '<p class="pg-subtitle">'
        'Paste an email message to identify suspicious indicators.'
        '</p>',
        unsafe_allow_html=True
    )

    email = st.text_area(
        "Email content",
        height=200,
        placeholder="Paste the complete email message here...",
        key="email_input",
        label_visibility="collapsed"
    )

    scan_col, reset_col = st.columns([3, 1])

    with scan_col:
        scan_email = st.button(
            "🔍 ANALYSE EMAIL",
            use_container_width=True
        )

    with reset_col:
        reset_email = st.button(
            "↻ RESET",
            use_container_width=True
        )

    if reset_email:
        st.session_state.email_result = None
        st.rerun()

    if scan_email:

        if not email.strip():

            st.warning("Please paste an email before analysing.")

        else:

            result = analyse_email(email)

            st.session_state.email_result = result

            st.session_state.history.append({
                "Date & Time": result["date"],
                "Type": "Email",
                "Risk Score": f"{result['score']}/100",
                "Classification": result["classification"],
                "Keywords Found": len(result["keywords"]),
                "URLs Found": len(result["urls"])
            })

            st.rerun()

    if st.session_state.email_result:

        result = st.session_state.email_result

        score = result["score"]

        st.divider()

        st.markdown("## 📊 Security Analysis Report")

        a, b, c = st.columns(3)

        a.metric("Risk Score", f"{score}/100")
        b.metric("Suspicious Keywords", len(result["keywords"]))
        c.metric("URLs Detected", len(result["urls"]))

        if score >= 45:

            st.error("🚨 HIGH RISK — Possible Phishing Email")

            st.markdown("""
            <div class="pg-card">
                <h3 style="color:#F87171;">High threat level</h3>
                <p style="color:#EAF4FF;">
                    Multiple suspicious indicators were found.
                    Do not click links or share sensitive information
                    without independently verifying the sender.
                </p>
            </div>
            """, unsafe_allow_html=True)

        elif score >= 15:

            st.warning("⚠️ MEDIUM RISK — Suspicious Email")

            st.markdown("""
            <div class="pg-card">
                <h3 style="color:#FBBF24;">Moderate threat level</h3>
                <p style="color:#EAF4FF;">
                    Some suspicious indicators were detected.
                    Verify the sender and message before taking action.
                </p>
            </div>
            """, unsafe_allow_html=True)

        else:

            st.success("✅ LOW RISK — No Listed Indicators Detected")

            st.markdown("""
            <div class="pg-card">
                <h3 style="color:#4ADE80;">Low detected threat level</h3>
                <p style="color:#EAF4FF;">
                    No indicators covered by this basic scanner
                    were found. This does not prove the email is safe.
                </p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### Risk Level")

        st.progress(score / 100)

        st.caption(
            "Risk score is based on the detection rules currently "
            "implemented in PhishGuard."
        )

        # Risk breakdown

        with st.expander("📈 View Risk Score Breakdown"):

            st.write(
                f"**Keyword points:** {result['keyword_points']}/60"
            )

            st.write(
                f"**Suspicious URL points:** {result['url_points']}/50"
            )

            st.write(
                f"**Final score:** {score}/100"
            )

            st.info(
                "The score combines keyword points and suspicious "
                "URL points, capped at 100."
            )

        # Keyword analysis

        st.markdown("### 🚩 Suspicious Keywords")

        if result["keywords"]:

            for word in result["keywords"]:
                st.markdown(f"- ⚠️ `{word}`")

        else:

            st.write("No suspicious keywords detected.")

        # URL analysis

        st.markdown("### 🔗 Website Link Analysis")

        if result["urls"]:

            for url in result["urls"]:

                st.code(url, language=None)

                if url in result["url_reasons"]:

                    for reason in result["url_reasons"][url]:
                        st.warning(reason)

        else:

            st.write("No website links found.")

        # Recommendations

        st.markdown("### 🛡️ Security Recommendations")

        if score >= 45:

            st.error("""
            - Do not click any links in this message.
            - Do not share passwords or financial details.
            - Verify the sender through an official contact method.
            - Report the message as suspected phishing.
            """)

        elif score >= 15:

            st.warning("""
            - Check the sender's email address carefully.
            - Avoid opening unexpected links.
            - Verify any urgent requests independently.
            - Do not share confidential information.
            """)

        else:

            st.success("""
            - Continue checking the sender's identity.
            - Be careful with unexpected attachments.
            - Avoid sharing sensitive information unnecessarily.
            - Remember that a low score does not guarantee safety.
            """)

        # PDF download

        st.divider()

        st.markdown("### 📄 Download Security Report")

        pdf_data = generate_pdf(result)

        st.download_button(
            label="📄 DOWNLOAD PDF SECURITY REPORT",
            data=pdf_data,
            file_name="PhishGuard_Security_Report.pdf",
            mime="application/pdf",
            use_container_width=True
        )


# =====================================================
# TAB 2 - URL CHECKER
# =====================================================

with tab2:

    st.markdown("## 🔗 Website URL Security Checker")

    st.markdown(
        '<p class="pg-subtitle">'
        'Check a website link for selected suspicious URL patterns.'
        '</p>',
        unsafe_allow_html=True
    )

    url_input = st.text_input(
        "Website URL",
        placeholder="Example: http://bit.ly/example"
    )

    if st.button("🔍 CHECK WEBSITE URL", use_container_width=True):

        if not url_input.strip():

            st.warning("Please enter a website URL.")

        else:

            checked = analyse_single_url(url_input)

            st.session_state.url_result = checked

            st.session_state.history.append({
                "Date & Time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                "Type": "URL",
                "Risk Score": "Pattern check",
                "Classification": (
                    "SUSPICIOUS PATTERN"
                    if checked["suspicious"]
                    else "NO LISTED PATTERN"
                ),
                "Keywords Found": 0,
                "URLs Found": 1
            })

    if st.session_state.url_result:

        checked = st.session_state.url_result

        st.divider()

        st.markdown("### URL Analysis Result")

        st.code(checked["url"], language=None)

        if checked["suspicious"]:

            st.error("⚠️ Suspicious URL patterns detected")

        else:

            st.success("✅ No listed suspicious URL patterns detected")

        st.markdown("### Analysis Details")

        for reason in checked["reasons"]:
            st.write(f"- {reason}")

        st.caption(
            "This checker uses simple pattern matching. It does not "
            "visit the website, check its reputation, or confirm that "
            "the destination is safe."
        )


# =====================================================
# TAB 3 - SCAN HISTORY
# =====================================================

with tab3:

    st.markdown("## 📜 Scan History")

    st.markdown(
        '<p class="pg-subtitle">'
        'Review the scans performed during this application session.'
        '</p>',
        unsafe_allow_html=True
    )

    if st.session_state.history:

        st.dataframe(
            st.session_state.history,
            use_container_width=True,
            hide_index=True
        )

        csv_buffer = StringIO()

        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=st.session_state.history[0].keys()
        )

        writer.writeheader()
        writer.writerows(st.session_state.history)

        st.download_button(
            "📥 DOWNLOAD SCAN HISTORY CSV",
            data=csv_buffer.getvalue(),
            file_name="PhishGuard_Scan_History.csv",
            mime="text/csv",
            use_container_width=True
        )

        if st.button("🗑️ CLEAR SCAN HISTORY"):

            st.session_state.history = []
            st.session_state.email_result = None
            st.session_state.url_result = None

            st.rerun()

    else:

        st.info("No scans available. Start by analysing an email or URL.")


# =====================================================
# TAB 4 - ABOUT
# =====================================================

with tab4:

    st.markdown("## ℹ️ About PhishGuard")

    st.markdown("""
    <div class="pg-card">
        <h3>Project Overview</h3>
        <p>
            PhishGuard is a cybersecurity application designed to
            identify potential phishing indicators in email messages
            and website links.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Core Features")

    feature1, feature2 = st.columns(2)

    with feature1:

        st.markdown("""
        <div class="pg-card">
            <h4>📧 Email Analysis</h4>
            <p>Detects selected suspicious keywords and URLs.</p>
        </div>
        <div class="pg-card">
            <h4>📊 Risk Scoring</h4>
            <p>Calculates a score using the implemented detection rules.</p>
        </div>
        <div class="pg-card">
            <h4>📜 Scan History</h4>
            <p>Displays scans performed during the current session.</p>
        </div>
        """, unsafe_allow_html=True)

    with feature2:

        st.markdown("""
        <div class="pg-card">
            <h4>🔗 URL Analysis</h4>
            <p>Checks links for selected suspicious patterns.</p>
        </div>
        <div class="pg-card">
            <h4>📄 PDF Reports</h4>
            <p>Creates downloadable email analysis reports.</p>
        </div>
        <div class="pg-card">
            <h4>🛡️ Security Guidance</h4>
            <p>Provides recommendations based on the scan result.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### Technology Stack")

    st.write("**Programming Language:** Python")
    st.write("**Web Framework:** Streamlit")
    st.write("**Pattern Detection:** Python Regular Expressions")
    st.write("**PDF Generation:** ReportLab")
    st.write("**Development Environment:** Visual Studio Code")

    st.markdown("### Important Limitations")

    st.warning("""
    - PhishGuard uses rule-based detection, not machine learning.
    - It does not verify sender identity or email authentication.
    - It does not visit URLs or query live website reputation services.
    - Scan history is stored in the current session and is not a permanent database.
    - A low-risk result does not guarantee that an email or website is safe.
    """)


# =====================================================
# FOOTER
# =====================================================

st.divider()

st.markdown("""
<div class="pg-footer">
    🛡️ <b>PhishGuard</b> | Cybersecurity Capstone Project
    <br><br>
    Developed by Gollapudi Keziya
    <br>
    LaunchED Global Internship
    <br><br>
    Email Threat Analysis System
</div>
""", unsafe_allow_html=True)
