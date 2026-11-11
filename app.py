import streamlit as st
import pandas as pd
import plotly.express as px
import re
import hmac
import html
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import urlparse

from utils.analyzer import analyze_message


# =========================================================
# PAGE CONFIGURATION
# =========================================================
st.set_page_config(
    page_title="TrustLens AI | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# SESSION STATE
# =========================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if "history" not in st.session_state:
    st.session_state.history = []

if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None


# =========================================================
# HIGH-VISIBILITY THEME
# =========================================================
st.markdown(
    """
    <style>
    .stApp {
        background: #080F1E;
        color: #FFFFFF;
    }

    h1, h2, h3, h4, h5, p, label {
        color: #FFFFFF !important;
    }

    section[data-testid="stSidebar"] {
        background: #101B30;
        border-right: 1px solid #36547D;
    }

    section[data-testid="stSidebar"] * {
        color: #FFFFFF !important;
    }

    section[data-testid="stSidebar"] label {
        font-size: 16px !important;
        font-weight: 800 !important;
    }

    /* =====================================================
       HIGH-VISIBILITY INPUTS (including the actual textarea)
       Keep this CSS inside the <style> block.
       ===================================================== */
    div[data-baseweb="input"],
    div[data-baseweb="textarea"],
    div[data-baseweb="select"],
    .stTextInput div[data-baseweb="input"],
    .stTextArea div[data-baseweb="textarea"] {
        background-color: #172640 !important;
        border: 2px solid #60A5FA !important;
        border-radius: 12px !important;
        opacity: 1 !important;
    }

    /* Force the textarea itself to use a dark background + white text */
    .stTextArea textarea,
    div[data-baseweb="textarea"] textarea,
    textarea {
        background-color: #172640 !important;
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        font-size: 18px !important;
        font-weight: 700 !important;
        line-height: 1.7 !important;
        caret-color: #FFFFFF !important;
        opacity: 1 !important;
        border: 0 !important;
    }

    /* Text input fields */
    .stTextInput input,
    div[data-baseweb="input"] input,
    div[data-baseweb="select"] input {
        background-color: #172640 !important;
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        font-size: 17px !important;
        font-weight: 700 !important;
        caret-color: #FFFFFF !important;
        opacity: 1 !important;
    }

    /* Clearly visible placeholders */
    .stTextArea textarea::placeholder,
    div[data-baseweb="textarea"] textarea::placeholder,
    .stTextInput input::placeholder,
    div[data-baseweb="input"] input::placeholder {
        color: #BFD7F5 !important;
        -webkit-text-fill-color: #BFD7F5 !important;
        opacity: 1 !important;
    }

    .stTextInput label,
    .stTextArea label,
    .stSelectbox label {
        color: #FFFFFF !important;
        font-size: 17px !important;
        font-weight: 900 !important;
    }

    .stTextArea [data-baseweb="textarea"]:focus-within,
    .stTextInput [data-baseweb="input"]:focus-within {
        border: 2px solid #38BDF8 !important;
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.35) !important;
    }

    /* Buttons */
    .stButton > button,
    .stFormSubmitButton > button {
        background: #1677FF !important;
        color: #FFFFFF !important;
        border: 1px solid #75B4FF !important;
        border-radius: 10px !important;
        min-height: 46px;
        font-size: 15px !important;
        font-weight: 900 !important;
    }

    .stButton > button:hover,
    .stFormSubmitButton > button:hover {
        background: #075BD8 !important;
        color: #FFFFFF !important;
        border: 1px solid #FFFFFF !important;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: #172640 !important;
        border: 1px solid #5276A5 !important;
        border-radius: 14px !important;
        padding: 20px !important;
    }

    div[data-testid="stMetricLabel"] {
        color: #E2EFFF !important;
        font-size: 15px !important;
        font-weight: 800 !important;
    }

    div[data-testid="stMetricValue"] {
        color: #FFFFFF !important;
        font-size: 30px !important;
        font-weight: 900 !important;
    }

    /* Custom cards */
    .custom-card {
        background: #172640;
        border: 1px solid #5276A5;
        border-radius: 13px;
        padding: 18px 20px;
        margin: 10px 0;
        color: #FFFFFF !important;
    }

    .custom-card h3,
    .custom-card p,
    .custom-card span {
        color: #FFFFFF !important;
    }

    .custom-card p {
        font-size: 16px;
        font-weight: 650;
        line-height: 1.7;
    }

    /* Notices */
    .notice {
        padding: 15px 18px;
        border-radius: 10px;
        margin: 12px 0;
        font-size: 16px;
        font-weight: 800;
        line-height: 1.6;
        color: #FFFFFF !important;
    }

    .notice-success {
        background: #103D32;
        border: 2px solid #21C997;
    }

    .notice-error {
        background: #4A1D27;
        border: 2px solid #FF647C;
    }

    .notice-warning {
        background: #493715;
        border: 2px solid #FFC857;
    }

    .notice-info {
        background: #12365B;
        border: 2px solid #48A6FF;
    }

    /* HTML history table - reliable text visibility */
    .history-wrap {
        width: 100%;
        overflow-x: auto;
        border: 2px solid #5276A5;
        border-radius: 12px;
        margin: 12px 0 20px 0;
    }

    table.history-table {
        width: 100%;
        min-width: 850px;
        border-collapse: collapse;
        background: #172640;
    }

    .history-table th {
        background: #075BD8;
        color: #FFFFFF !important;
        font-size: 16px;
        font-weight: 900;
        text-align: left;
        padding: 15px;
        border: 1px solid #6B91C0;
        white-space: nowrap;
    }

    .history-table td {
        background: #172640;
        color: #FFFFFF !important;
        font-size: 15px;
        font-weight: 700;
        padding: 14px 15px;
        border: 1px solid #5276A5;
        vertical-align: top;
    }

    .history-table tr:nth-child(even) td {
        background: #203653;
    }

    .history-message {
        min-width: 260px;
        max-width: 420px;
        white-space: normal;
        overflow-wrap: anywhere;
    }

    .risk-suspicious {
        color: #FF9AAA !important;
        font-weight: 900;
    }

    .risk-safe {
        color: #69E5B8 !important;
        font-weight: 900;
    }

    .login-panel {
        background: #111F36;
        border: 1px solid #5276A5;
        border-radius: 18px;
        padding: 25px;
        text-align: center;
    }

    .stCaption {
        color: #CBD5E1 !important;
    }

    hr {
        border-color: #36547D !important;
    }
    /* FINAL OVERRIDE: force readable text in Streamlit widgets */
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stTextInput"] input,
    div[data-testid="stTextArea"] [data-baseweb="textarea"] textarea,
    div[data-testid="stTextInput"] [data-baseweb="input"] input,
    textarea,
    input[type="text"],
    input[type="password"] {
        background: #172640 !important;
        background-color: #172640 !important;
        color: #FFFFFF !important;
        -webkit-text-fill-color: #FFFFFF !important;
        opacity: 1 !important;
        font-size: 18px !important;
        font-weight: 700 !important;
        caret-color: #FFFFFF !important;
        color-scheme: dark !important;
    }

    div[data-testid="stTextArea"] [data-baseweb="textarea"],
    div[data-testid="stTextInput"] [data-baseweb="input"] {
        background: #172640 !important;
        background-color: #172640 !important;
        border: 2px solid #60A5FA !important;
        border-radius: 12px !important;
    }

    div[data-testid="stTextArea"] textarea::placeholder,
    div[data-testid="stTextInput"] input::placeholder,
    textarea::placeholder,
    input::placeholder {
        color: #C9DDF5 !important;
        -webkit-text-fill-color: #C9DDF5 !important;
        opacity: 1 !important;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================
def show_notice(message, kind="info"):
    allowed_kinds = {"success", "error", "warning", "info"}
    if kind not in allowed_kinds:
        kind = "info"

    safe_message = html.escape(str(message))
    st.markdown(
        f'<div class="notice notice-{kind}">{safe_message}</div>',
        unsafe_allow_html=True
    )


def render_history_table(dataframe):
    """Render a high-contrast HTML table instead of the canvas-based grid."""
    columns = [
        "Date",
        "Message",
        "Risk",
        "Risk Level",
        "Score",
        "Confidence"
   ]
    display_df = dataframe.copy()

    for column in columns:
        if column not in display_df.columns:
            display_df[column] = ""

    display_df = display_df[columns]

    header_html = "".join(
        f"<th>{html.escape(str(column))}</th>" for column in columns
    )

    rows_html = []
    for _, row in display_df.iterrows():
        risk_text = str(row["Risk"])
        risk_class = (
            "risk-suspicious"
            if risk_text.strip().lower() == "suspicious"
            else "risk-safe"
            if risk_text.strip().lower() == "safe"
            else ""
        )

        cells = []
        for column in columns:
            value = html.escape(str(row[column]))
            if column == "Message":
                cells.append(
                    f'<td><div class="history-message">{value}</div></td>'
                )
            elif column == "Risk":
                cells.append(
                    f'<td><span class="{risk_class}">{value}</span></td>'
                )
            else:
                cells.append(f"<td>{value}</td>")

        rows_html.append("<tr>" + "".join(cells) + "</tr>")

    table_html = f"""
    <div class="history-wrap">
      <table class="history-table">
        <thead><tr>{header_html}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
      </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


def get_credentials():
    """Read credentials from Streamlit secrets."""
    try:
        auth = st.secrets["auth"]
        username = str(auth["username"])
        password = str(auth["password"])
        return username, password
    except Exception:
        return None, None


# =========================================================
# LOGIN PAGE
# =========================================================
def login_page():
    st.markdown("<br><br>", unsafe_allow_html=True)

    left, center, right = st.columns([1, 1.2, 1])

    with center:
        st.markdown(
            """
            <div class="login-panel">
                <h1>🛡️ TrustLens AI</h1>
                <h3 style="color:#69AFFF !important;">Secure Login</h3>
                <p>Intelligent Payment Message Security Analyzer</p>
                <hr>
                <h3>Welcome Back!</h3>
                <p>Sign in to access your security dashboard.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.write("")

        with st.form("login_form"):
            username = st.text_input(
                "Username",
                placeholder="Enter your username"
            )
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password"
            )
            submitted = st.form_submit_button(
                "🔐 LOGIN TO DASHBOARD",
                use_container_width=True
            )

        if submitted:
            if not username.strip() or not password:
                show_notice(
                    "Please enter both username and password.",
                    "warning"
                )
            else:
                correct_username, correct_password = get_credentials()

                if correct_username is None or correct_password is None:
                    show_notice(
                        "Login credentials are not configured. "
                        "Create .streamlit/secrets.toml with an [auth] section.",
                        "error"
                    )
                else:
                    username_ok = hmac.compare_digest(
                        username.strip(), correct_username
                    )
                    password_ok = hmac.compare_digest(
                        password, correct_password
                    )

                    if username_ok and password_ok:
                        st.session_state.authenticated = True
                        st.rerun()
                    else:
                        show_notice(
                            "Invalid username or password. Please try again.",
                            "error"
                        )

        st.markdown(
            """
            <p style="text-align:center;color:#CBD5E1 !important;
            font-size:13px;">
                © 2026 TrustLens AI | Secure Access
            </p>
            """,
            unsafe_allow_html=True
        )


# =========================================================
# LOGIN GATE - KEEP BEFORE SIDEBAR AND DASHBOARD
# =========================================================
if not st.session_state.authenticated:
    login_page()
    st.stop()


# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.markdown(
        """
        <div style="text-align:center;padding:12px 4px;">
            <h1>🛡️ TrustLens AI</h1>
            <p style="color:#69AFFF !important;font-weight:800;">
                Payment Security Platform
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Message Analyzer",
            "Link Checker",
            "Analysis History",
            "About"
        ]
    )

    st.markdown("---")
    st.markdown(
        """
        <p style="color:#CBD5E1 !important;">Account Status</p>
        <h4 style="color:#69E5B8 !important;">● Logged In</h4>
        """,
        unsafe_allow_html=True
    )

    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.last_analysis = None
        st.rerun()


# =========================================================
# OVERVIEW
# =========================================================
if page == "Overview":
    st.title("🛡️ Security Overview")
    st.caption(
        "Monitor payment message analysis and suspicious activity."
    )
    st.markdown("---")

    history_df = pd.DataFrame(st.session_state.history)
    total = len(history_df)

    if total:
        risk_series = history_df["Risk"].astype(str).str.strip().str.lower()
        suspicious = int((risk_series == "suspicious").sum())
        safe = int((risk_series == "safe").sum())
        detection_rate = suspicious / total * 100
    else:
        suspicious = 0
        safe = 0
        detection_rate = 0.0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📊 Total Analyses", total)
    c2.metric("🚨 Suspicious Messages", suspicious)
    c3.metric("✅ Safe Messages", safe)
    c4.metric("🎯 Suspicious Rate", f"{detection_rate:.1f}%")

    st.markdown("---")
    st.subheader("📈 Security Analytics")

    if total:
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            risk_data = pd.DataFrame({
                "Category": ["Suspicious", "Safe"],
                "Count": [suspicious, safe]
            })
            fig = px.pie(
                risk_data,
                names="Category",
                values="Count",
                title="Message Risk Distribution",
                hole=0.55,
                color="Category",
                color_discrete_map={
                    "Suspicious": "#FF526F",
                    "Safe": "#21C997"
                }
            )
            fig.update_layout(
                paper_bgcolor="#111F36",
                plot_bgcolor="#111F36",
                font_color="#FFFFFF",
                title_font_color="#FFFFFF"
            )
            st.plotly_chart(fig, use_container_width=True)

        with chart_col2:
            trend_df = history_df.copy()
            trend_df["Date"] = pd.to_datetime(
                trend_df["Date"],
                format="%d-%m-%Y %I:%M:%S %p IST",
                errors="coerce"
            ).dt.strftime("%d %b")
            trend = (
                trend_df.dropna(subset=["Date"])
                .groupby(["Date", "Risk"])
                .size()
                .reset_index(name="Count")
            )
            if not trend.empty:
                fig2 = px.bar(
                    trend,
                    x="Date",
                    y="Count",
                    color="Risk",
                    title="Analysis Activity",
                    barmode="group",
                    color_discrete_map={
                        "Suspicious": "#FF526F",
                        "Safe": "#21C997"
                    }
                )
                fig2.update_layout(
                    paper_bgcolor="#111F36",
                    plot_bgcolor="#111F36",
                    font_color="#FFFFFF",
                    title_font_color="#FFFFFF"
                )
                st.plotly_chart(fig2, use_container_width=True)
            else:
                show_notice("No valid dates are available for the trend chart.", "info")
    else:
        show_notice(
            "No messages analyzed yet. Open Message Analyzer to begin.",
            "info"
        )

    st.markdown("---")
    st.subheader("⚡ Recent Activity")
    if total:
        render_history_table(history_df.tail(5).iloc[::-1])
    else:
        st.markdown(
            """
            <div class="custom-card">
                <h3>Welcome to TrustLens AI</h3>
                <p>Your recent security analysis activity will appear here.</p>
            </div>
            """,
            unsafe_allow_html=True
        )


# =========================================================
# MESSAGE ANALYZER
# =========================================================
elif page == "Message Analyzer":
    st.title("🔍 Payment Message Analyzer")
    st.write(
        "Analyze payment-related messages to identify suspicious "
        "patterns and possible fraud indicators."
    )
    st.markdown("---")

    message = st.text_area(
        "Enter Payment Message",
        height=200,
        placeholder="Paste your payment message here...",
        key="payment_message"
    )

    if st.button("🚀 Analyze Message", use_container_width=True):
        if not message.strip():
            show_notice("Please enter a message before analysis.", "warning")
        else:
            try:
                with st.spinner("Analyzing message..."):
                    result = analyze_message(message)

                if not isinstance(result, dict):
                    raise ValueError(
                        "analyze_message() must return a dictionary."
                    )

                score = result.get("score", 0)
                risk = str(result.get("risk", "Unknown"))
                classification = str(
                    result.get("classification", "Unknown")
     )
                recommendation = result.get("recommendation", "")
                indicators = result.get("indicators", [])
                confidence = result.get("confidence", 0)

                if indicators is None:
                    indicators = []
                elif isinstance(indicators, str):
                    indicators = [indicators]

                st.session_state.last_analysis = {
                    "score": score,
                    "risk": risk,
                    "indicators": indicators,
                    "confidence": confidence
                }

                risk_normalized = risk.strip().lower()
                st.markdown("---")
                st.subheader("📋 Analysis Results")

                r1, r2, r3 = st.columns(3)
                r1.metric("Risk Score", str(score))
                r2.metric("Risk Level", risk)
                r3.metric("Confidence", str(confidence))

                if classification == "Suspicious":
                    show_notice(
                        f"Warning: {risk} detected. "
                        "Verify the message through official channels.",
                        "error"
                   )

                else:
                    show_notice(
                        f"{risk}: No strong suspicious patterns detected. "
                        "Always verify payment requests independently.",
                        "success"
        )

                st.subheader("💡 Recommended Action")
                show_notice(recommendation, "info")

                st.subheader("🚩 Detected Indicators")
                if indicators:
                    for item in indicators:
                        st.markdown(
                            f"""
                            <div class="custom-card">
                                <p>⚠️ {html.escape(str(item))}</p>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                else:
                    show_notice(
                        "No indicators were returned by the analyzer.",
                        "info"
                    )

                india_time = datetime.now(
                    ZoneInfo("Asia/Kolkata")
                ) 
                st.session_state.history.append({
                    "Date": india_time.strftime("%d-%m-%Y %I:%M:%S %p IST"),
                    "Message": message,
                    "Risk": risk,
                    "Score": score,
                    "Confidence": confidence
              })

            except Exception as error:
                show_notice(f"Analysis failed: {error}", "error")


# =========================================================
# LINK CHECKER
# =========================================================
elif page == "Link Checker":
    st.title("🔗 Suspicious Link Checker")
    st.write("Check a URL for basic suspicious patterns.")
    st.markdown("---")

    url = st.text_input(
        "Enter Website URL",
        placeholder="https://example.com"
    )

    if st.button("🔍 Check Link", use_container_width=True):
        if not url.strip():
            show_notice("Please enter a website URL.", "warning")
        else:
            candidate = url.strip()
            parsed = urlparse(
                candidate if "://" in candidate else "https://" + candidate
            )

            if not parsed.netloc or "." not in parsed.netloc:
                show_notice(
                    "Please enter a valid-looking website address.",
                    "warning"
                )
            else:
                suspicious_patterns = [
                    r"^http://",
                    r"@",
                    r"bit\.ly",
                    r"tinyurl",
                    r"free",
                    r"verify",
                    r"login",
                    r"secure-update",
                    r"account-alert"
                ]

                matches = [
                    pattern
                    for pattern in suspicious_patterns
                    if re.search(pattern, candidate, re.IGNORECASE)
                ]

                if matches:
                    show_notice(
                        "Potentially suspicious URL patterns were found. "
                        "Do not enter personal or payment details until "
                        "you independently verify the website.",
                        "error"
                    )
                    st.subheader("Detected Patterns")
                    for item in matches:
                        st.markdown(
                            f'<div class="custom-card"><p>⚠️ '
                            f'{html.escape(item)}</p></div>',
                            unsafe_allow_html=True
                        )
                else:
                    show_notice(
                        "No listed suspicious patterns were detected. "
                        "This does not prove the website is safe.",
                        "success"
                    )

                st.info(
                    "This is a basic pattern checker, not a full URL "
                    "reputation, phishing, or malware detection service."
                )


# =========================================================
# ANALYSIS HISTORY
# =========================================================
elif page == "Analysis History":
    st.title("📜 Analysis History")
    st.write("View previous payment message analysis results.")
    st.markdown("---")

    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)

        # Use HTML table for clear, high-contrast text in every cell.
        render_history_table(history_df.iloc[::-1])

        csv_data = history_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download History as CSV",
            data=csv_data,
            file_name="trustlens_analysis_history.csv",
            mime="text/csv",
            use_container_width=True
        )

        if st.button("🗑️ Clear Analysis History", use_container_width=True):
            st.session_state.history = []
            st.session_state.last_analysis = None
            st.rerun()
    else:
        show_notice(
            "No analysis history available. Analyze a message to create "
            "your first history entry.",
            "info"
        )


# =========================================================
# ABOUT
# =========================================================
elif page == "About":
    st.title("ℹ️ About TrustLens AI")

    st.markdown(
        """
        <div class="custom-card">
            <h3>🛡️ TrustLens AI</h3>
            <p>
                TrustLens AI is an experimental payment message security
                analyzer designed to identify suspicious patterns in
                payment-related messages.
            </p>
            <p>
                The platform provides message analysis, basic suspicious
                link pattern checking, security analytics, and analysis
                history in one dashboard.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("✨ Core Features")
    features = [
        "Payment Message Analysis",
        "Suspicious Pattern Identification",
        "Basic URL Pattern Checking",
        "Security Analytics Dashboard",
        "Analysis History and CSV Export"
    ]

    for feature in features:
        st.markdown(
            f"""
            <div class="custom-card">
                <p>✔️ {html.escape(feature)}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.caption("TrustLens AI | Hackathon Prototype | 2026")
