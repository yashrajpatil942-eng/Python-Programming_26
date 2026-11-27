"""
URL Guard — URL Checker & Phishing Detection System
File: app.py

A rule-based, offline cybersecurity Streamlit application designed for URL inspection,
suspicious indicator detection, risk scoring, and educational awareness.

Developed for first-year Computer Science Engineering college evaluation.
"""

from __future__ import annotations

import html
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

# ============================================================================
# 1. Streamlit Page Configuration (MUST be the absolute first Streamlit call)
# ============================================================================
st.set_page_config(
    page_title="URL Guard — Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Core & Storage Module Imports
from core.detector import (
    CHECK_ID_HTTPS,
    CHECK_ID_HYPHENS,
    CHECK_ID_IP,
    CHECK_ID_KEYWORDS,
    CHECK_ID_LENGTH,
    CHECK_ID_SPECIAL_CHARS,
    CHECK_ID_SUBDOMAINS,
    CheckResult,
    run_detection_checks,
)
from core.parser import ParsedURL, parse_url
from core.report_generator import AnalysisReport, generate_report
from core.risk_calculator import RiskLevel, RiskScoreResult, calculate_risk
from core.validator import ValidationResult, validate_url
from storage.history_manager import (
    clear_history,
    export_history_csv,
    get_history,
    save_scan,
)
from core.analytics import (
    FILTER_ALL_TIME,
    FILTER_LAST_7_DAYS,
    FILTER_TODAY,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    TIME_FILTERS,
    AnalyticsMetrics,
    clean_history_records,
    compute_metrics,
    filter_history_by_window,
    get_daily_trend_data,
    get_hourly_distribution_data,
    get_top_hostnames_data,
)
import plotly.graph_objects as go

# ============================================================================
# 2. Navigation Constants
# ============================================================================
PAGE_HOME = "🏠 Home / Dashboard"
PAGE_RESULTS = "📊 Analysis Results"
PAGE_ANALYTICS = "📈 Analytics & Trends"
PAGE_HISTORY = "📜 Scan History"
PAGE_ABOUT = "ℹ️ About Project"
PAGES = [PAGE_HOME, PAGE_RESULTS, PAGE_ANALYTICS, PAGE_HISTORY, PAGE_ABOUT]

# Demonstration Preset Samples for College Evaluator Walkthrough
PRESETS = [
    ("🟢 Safe (Google)", "https://www.google.com"),
    ("🟡 Unencrypted HTTP", "http://example.com"),
    ("🔴 IP Phishing", "http://192.168.1.1/banking/login"),
    ("🔴 Deceptive @ Spoof", "https://paypal.com@secure-update.com/login"),
    ("🔴 Multi-Subdomain Chain", "http://portal.login.verify.account.bank-update.com/auth"),
]

# ============================================================================
# 3. Dark Navy Cybersecurity CSS Theme
# ============================================================================
CYBER_CSS = """
<style>
/* Base Dark Navy Canvas */
.stApp {
    background-color: #0B1120 !important;
    color: #F8FAFC !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
}

/* Page Container Layout */
.block-container {
    padding-top: 1.8rem !important;
    padding-bottom: 3rem !important;
    max-width: 1200px !important;
}

/* Header & Sidebar Styling */
header[data-testid="stHeader"] {
    background-color: rgba(11, 17, 32, 0.85) !important;
    backdrop-filter: blur(8px) !important;
}

[data-testid="stSidebar"] {
    background-color: #0d1527 !important;
    border-right: 1px solid #1E293B !important;
}

[data-testid="stSidebar"] .stMarkdown h1, 
[data-testid="stSidebar"] .stMarkdown h2, 
[data-testid="stSidebar"] .stMarkdown h3 {
    color: #38BDF8 !important;
}

/* Typography Hierarchy */
h1, h2, h3, h4, h5, h6 {
    color: #F8FAFC !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
}

p, span, label {
    color: #CBD5E1;
}

/* Header Branding Banner */
.cyber-header-wrapper {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1.5rem;
    background: linear-gradient(180deg, #162032 0%, #0F172A 100%);
    border: 1px solid #1E293B;
    border-radius: 14px;
    box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
}

.cyber-header-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 56px;
    height: 56px;
    border-radius: 12px;
    background: rgba(6, 182, 212, 0.12);
    border: 1px solid rgba(6, 182, 212, 0.35);
    flex-shrink: 0;
}

.cyber-title {
    margin: 0 !important;
    font-size: 2.2rem !important;
    font-weight: 800 !important;
    background: linear-gradient(135deg, #38BDF8 0%, #06B6D4 50%, #10B981 100%);
    -webkit-background-clip: text !important;
    -webkit-text-fill-color: transparent !important;
    letter-spacing: -0.03em !important;
}

.cyber-tagline {
    margin: 3px 0 0 0 !important;
    font-size: 0.95rem !important;
    color: #94A3B8 !important;
    font-weight: 600 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
}

/* Cyber Cards */
.cyber-card {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25), 0 2px 4px -2px rgba(0, 0, 0, 0.25);
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}

.cyber-card:hover {
    border-color: #475569;
    box-shadow: 0 8px 16px -2px rgba(0, 0, 0, 0.35);
}

.cyber-card-flagged {
    border-left: 4px solid #EF4444 !important;
}

.cyber-card-warning {
    border-left: 4px solid #F59E0B !important;
}

.cyber-card-safe {
    border-left: 4px solid #10B981 !important;
}

/* Status Badges */
.cyber-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.75rem;
    font-size: 0.75rem;
    font-weight: 700;
    border-radius: 9999px;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

.cyber-badge-high {
    background-color: rgba(239, 68, 68, 0.15);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.cyber-badge-medium {
    background-color: rgba(245, 158, 11, 0.15);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.4);
}

.cyber-badge-low {
    background-color: rgba(16, 185, 129, 0.15);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

.cyber-badge-cyan {
    background-color: rgba(6, 182, 212, 0.15);
    color: #38BDF8;
    border: 1px solid rgba(6, 182, 212, 0.4);
}

/* Streamlit Native Buttons */
div.stButton > button {
    background: linear-gradient(135deg, #06B6D4 0%, #0284C7 100%) !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    padding: 0.55rem 1.25rem !important;
    box-shadow: 0 4px 14px rgba(6, 182, 212, 0.3) !important;
    transition: all 0.2s ease-in-out !important;
}

div.stButton > button:hover {
    box-shadow: 0 6px 20px rgba(6, 182, 212, 0.5) !important;
    transform: translateY(-1px) !important;
}

div.stButton > button:active {
    transform: translateY(1px) !important;
}

/* Secondary Button Styling */
div.stButton > button[kind="secondary"] {
    background: #1E293B !important;
    color: #E2E8F0 !important;
    border: 1px solid #334155 !important;
    box-shadow: none !important;
}

div.stButton > button[kind="secondary"]:hover {
    background: #334155 !important;
    border-color: #475569 !important;
}

/* Input Fields */
div[data-baseweb="input"] {
    background-color: #1E293B !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
}

div[data-baseweb="input"]:focus-within {
    border-color: #06B6D4 !important;
    box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.25) !important;
}

div[data-baseweb="input"] input {
    background-color: transparent !important;
    color: #F8FAFC !important;
}

/* Disclaimer Banner */
.cyber-disclaimer {
    background: #162032;
    border: 1px solid #334155;
    border-left: 4px solid #06B6D4;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-top: 1.5rem;
    color: #94A3B8;
    font-size: 0.875rem;
    line-height: 1.55;
}

/* Dataframe and Tables */
[data-testid="stDataFrame"], [data-testid="stTable"] {
    border-radius: 10px !important;
    border: 1px solid #334155 !important;
    background-color: #1E293B !important;
    overflow: hidden !important;
}

/* Progress bar container */
.stProgress > div > div > div > div {
    background-color: #06B6D4 !important;
}

/* Metric Card Styling */
[data-testid="stMetric"] {
    background-color: #1E293B !important;
    border: 1px solid #334155 !important;
    border-radius: 12px !important;
    padding: 1rem 1.25rem !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
}

[data-testid="stMetric"]:hover {
    border-color: #06B6D4 !important;
    box-shadow: 0 0 14px rgba(6, 182, 212, 0.2) !important;
    transform: translateY(-2px) !important;
}

[data-testid="stMetricValue"] {
    font-size: 1.85rem !important;
    font-weight: 800 !important;
    color: #F8FAFC !important;
    letter-spacing: -0.02em !important;
}

[data-testid="stMetricLabel"] {
    font-size: 0.8rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    color: #94A3B8 !important;
}

/* Card Glowing Accents on Hover */
.cyber-card-flagged:hover {
    border-color: #EF4444 !important;
    box-shadow: 0 0 16px rgba(239, 68, 68, 0.25) !important;
}

.cyber-card-warning:hover {
    border-color: #F59E0B !important;
    box-shadow: 0 0 16px rgba(245, 158, 11, 0.25) !important;
}

.cyber-card-safe:hover {
    border-color: #10B981 !important;
    box-shadow: 0 0 16px rgba(16, 185, 129, 0.2) !important;
}

/* Expander Dark Styling */
details[data-testid="stExpander"] {
    background-color: #1E293B !important;
    border: 1px solid #334155 !important;
    border-radius: 10px !important;
    margin-bottom: 0.75rem !important;
}

details[data-testid="stExpander"] > summary {
    color: #F8FAFC !important;
    font-weight: 600 !important;
}

/* Button Text Wrap Resilience */
div.stButton > button {
    white-space: normal !important;
    word-break: break-word !important;
}

/* Sidebar Radio pill / highlight */
[data-testid="stSidebar"] div[role="radiogroup"] > label {
    padding: 0.4rem 0.75rem !important;
    border-radius: 8px !important;
    transition: background-color 0.15s ease !important;
}

[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background-color: rgba(56, 189, 248, 0.08) !important;
}
</style>
"""

# ============================================================================
# 4. Session State Management
# ============================================================================
def init_session_state() -> None:
    """Ensure all required session state keys exist with clean defaults."""
    defaults = {
        "current_page": PAGE_HOME,
        "url_input_value": "",
        "validation_error": None,
        "current_report": None,
        "parsed_url": None,
        "check_results": None,
        "risk_result": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ============================================================================
# 5. Core Pipeline Orchestrator Function
# ============================================================================
def run_scan_and_navigate(url_to_scan: str) -> bool:
    """
    Executes the full URL inspection pipeline:
    1. Validation
    2. Component Parsing & Normalization
    3. 7 Suspicious Feature Detection Checks
    4. Risk Calculation & Classification
    5. Report Compilation
    6. Sanitized Scan History Persistence

    Returns True if scan was successful and routed to Results; False if validation failed.
    """
    validation: ValidationResult = validate_url(url_to_scan)
    if not validation.is_valid:
        st.session_state["validation_error"] = validation.error_message or "Invalid URL input."
        st.session_state["current_report"] = None
        st.session_state["parsed_url"] = None
        st.session_state["check_results"] = None
        st.session_state["risk_result"] = None
        st.session_state["current_page"] = PAGE_HOME
        return False

    st.session_state["validation_error"] = None
    parsed: ParsedURL = parse_url(url_to_scan, validation)
    checks: List[CheckResult] = run_detection_checks(parsed)
    risk: RiskScoreResult = calculate_risk(checks)
    report: AnalysisReport = generate_report(parsed, checks, risk)
    save_scan(report)

    st.session_state["current_report"] = report
    st.session_state["parsed_url"] = parsed
    st.session_state["check_results"] = checks
    st.session_state["risk_result"] = risk
    st.session_state["current_page"] = PAGE_RESULTS
    return True


# ============================================================================
# 6. Reusable Visual Components
# ============================================================================
def render_header() -> None:
    """Renders the top branding header with SVG shield icon, title, and tagline."""
    header_html = """
    <div class="cyber-header-wrapper">
        <div class="cyber-header-icon">
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#06B6D4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
            </svg>
        </div>
        <div>
            <h1 class="cyber-title">URL GUARD</h1>
            <p class="cyber-tagline">Analyse. Detect. Stay Aware.</p>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_risk_score_hero(report: AnalysisReport) -> None:
    """Renders high-impact risk score metric card with classification badge and progress gauge."""
    badge_bg = f"{report.badge_color}22"
    badge_border = report.badge_color
    badge_text = report.badge_color

    score_html = f"""
    <div class="cyber-card" style="text-align: center; padding: 2.2rem 1.5rem; border-top: 4px solid {report.badge_color};">
        <div style="font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.12em; color: #94A3B8; margin-bottom: 8px;">
            Heuristic Risk Assessment Score
        </div>
        <div style="font-size: 3.8rem; font-weight: 800; color: #F8FAFC; line-height: 1; margin-bottom: 12px;">
            {report.total_risk_score} <span style="font-size: 1.6rem; font-weight: 500; color: #64748B;">/ 100</span>
        </div>
        <div>
            <span style="display: inline-block; padding: 6px 20px; border-radius: 9999px; font-size: 1.05rem; font-weight: 700; background-color: {badge_bg}; color: {badge_text}; border: 1.5px solid {badge_border}; letter-spacing: 0.05em;">
                🛡️ {report.risk_classification}
            </span>
        </div>
        <div style="font-size: 0.8rem; color: #64748B; margin-top: 14px;">
            Rule-based heuristic score (0 = no indicators, 100 = maximum suspicion). Not a percentage probability.
        </div>
    </div>
    """
    st.markdown(score_html, unsafe_allow_html=True)
    # Native Streamlit progress bar for accessibility and programmatic testing
    st.progress(min(1.0, max(0.0, report.total_risk_score / 100.0)))


def render_check_card(check: CheckResult) -> None:
    """Renders a single detection check card with green/amber/red indicators and XSS-escaped evidence."""
    is_flagged = check.detected and check.points > 0
    status_class = "cyber-card-flagged" if check.points >= 15 else ("cyber-card-warning" if check.points > 0 else "cyber-card-safe")
    badge_class = "cyber-badge-high" if check.points >= 15 else ("cyber-badge-medium" if check.points > 0 else "cyber-badge-low")
    status_text = f"+{check.points} PTS • FLAGGED" if is_flagged else "0 PTS • PASSED"
    icon = "🚨" if is_flagged else "✅"

    escaped_name = html.escape(check.check_name, quote=True)
    escaped_explanation = html.escape(check.explanation, quote=True)
    escaped_evidence = html.escape(str(check.evidence), quote=True)

    card_html = f"""
    <div class="cyber-card {status_class}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-weight: 700; font-size: 1.05rem; color: #F8FAFC; display: flex; align-items: center; gap: 8px;">
                <span>{icon}</span>
                <span>{escaped_name}</span>
            </div>
            <span class="cyber-badge {badge_class}">{status_text}</span>
        </div>
        <p style="color: #94A3B8; font-size: 0.9rem; margin: 4px 0 10px 0; line-height: 1.45;">
            {escaped_explanation}
        </p>
        <div style="background: #0F172A; border: 1px solid #334155; border-radius: 6px; padding: 6px 12px; font-family: monospace; font-size: 0.8rem; color: #38BDF8; word-break: break-all;">
            <span style="color: #64748B;">Evidence:</span> {escaped_evidence}
        </div>
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


# ============================================================================
# 7. Page 1: Home / Dashboard
# ============================================================================
def render_home_page() -> None:
    """Renders Page 1: Home / Dashboard with URL input, presets, and guides."""
    render_header()

    st.markdown("### Intelligent Heuristic URL Inspection & Phishing Detection")
    st.markdown(
        "Inspect URL structures and discover suspicious indicators commonly found in deceptive and malicious links. "
        "Built strictly offline with zero external API dependencies or remote lookups."
    )

    # Preset Sample Demonstration Buttons for College Evaluator Demo
    st.markdown("#### ⚡ Quick Demonstration Presets")
    st.markdown("Click any preset below to test the detection engine with curated scenario URLs:")
    cols = st.columns(len(PRESETS))
    for idx, (label, sample_url) in enumerate(PRESETS):
        with cols[idx]:
            st.button(
                label,
                key=f"preset_btn_{idx}",
                on_click=run_scan_and_navigate,
                args=(sample_url,),
                use_container_width=True,
            )

    st.markdown("---")
    st.markdown("#### 🔍 Custom URL Inspection")

    # URL Input Form supporting both Enter key and Button click
    with st.form("url_analysis_form", clear_on_submit=False):
        url_input = st.text_input(
            "Enter Website URL for Inspection:",
            value=st.session_state.get("url_input_value", ""),
            placeholder="e.g. https://www.google.com or paste a suspicious link",
            key="input_url_field",
            help="Paste any website URL or hostname. Press Enter or click Analyse URL to inspect.",
        )
        submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)
        if submitted:
            if run_scan_and_navigate(url_input):
                st.rerun()

    # Validation Error Banner
    if st.session_state.get("validation_error"):
        st.error(f"❌ Input Error: {st.session_state['validation_error']}")

    # User Walkthrough Guide
    st.markdown("---")
    st.markdown("#### 📖 How to Use URL Guard")
    step_cols = st.columns(3)
    with step_cols[0]:
        st.markdown(
            """
            <div class="cyber-card">
                <div style="font-size: 1.15rem; font-weight: 700; color: #38BDF8; margin-bottom: 6px;">1. Submit URL</div>
                <p style="font-size: 0.88rem; color: #94A3B8; margin: 0;">
                    Paste any website link or select a quick demonstration preset. Supports HTTPS, HTTP, and bare domain names.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with step_cols[1]:
        st.markdown(
            """
            <div class="cyber-card">
                <div style="font-size: 1.15rem; font-weight: 700; color: #38BDF8; margin-bottom: 6px;">2. Heuristic Analysis</div>
                <p style="font-size: 0.88rem; color: #94A3B8; margin: 0;">
                    The engine applies 7 independent offline structural rules examining encryption, length, raw IP hosts, keywords, and subdomain depth.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with step_cols[2]:
        st.markdown(
            """
            <div class="cyber-card">
                <div style="font-size: 1.15rem; font-weight: 700; color: #38BDF8; margin-bottom: 6px;">3. Review Score</div>
                <p style="font-size: 0.88rem; color: #94A3B8; margin: 0;">
                    Evaluate the aggregate risk score (0-100), classification badge, rule evidence breakdown, and safety recommendation.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Academic Safety Disclaimer
    st.markdown(
        """
        <div class="cyber-disclaimer">
            <strong>⚠️ Academic Safety & Ethical Notice:</strong>
            URL Guard operates purely as a static, offline structural heuristic scanner.
            It does not visit, ping, or execute content from destination servers.
            A <strong>LOW RISK</strong> score indicates fewer structural indicators were detected,
            but <em>never guarantees</em> that a web resource is legitimate or safe.
            Always independently verify domain authenticity before sharing sensitive credentials or banking data.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================================
# 8. Page 2: Analysis Results
# ============================================================================
def render_results_page() -> None:
    """Renders Page 2: Analysis Results with risk metrics, cards, and breakdown table."""
    render_header()

    report: Optional[AnalysisReport] = st.session_state.get("current_report")
    parsed: Optional[ParsedURL] = st.session_state.get("parsed_url")
    checks: Optional[List[CheckResult]] = st.session_state.get("check_results")

    # Empty State Guard against direct navigation
    if report is None or parsed is None or checks is None:
        st.info("ℹ️ No URL has been analysed yet. Return to the Home Dashboard to perform an inspection.")
        if st.button("⬅️ Go to Home / Dashboard", key="btn_go_home"):
            st.session_state["current_page"] = PAGE_HOME
            st.rerun()
        return

    # Action navigation buttons
    nav_c1, nav_c2, nav_c3 = st.columns(3)
    with nav_c1:
        if st.button("🔍 Run Another Scan", key="btn_run_another", use_container_width=True):
            st.session_state["current_page"] = PAGE_HOME
            st.rerun()
    with nav_c2:
        if st.button("📈 View Analytics", key="btn_view_analytics_from_results", use_container_width=True):
            st.session_state["current_page"] = PAGE_ANALYTICS
            st.rerun()
    with nav_c3:
        if st.button("📜 View Scan History", key="btn_view_hist_from_results", use_container_width=True):
            st.session_state["current_page"] = PAGE_HISTORY
            st.rerun()

    # Safely Displayed Scanned URL (never rendered as raw HTML)
    st.markdown("#### Scanned URL:")
    st.code(report.original_url, language=None)

    # Top Metrics Row
    m_col1, m_col2, m_col3 = st.columns(3)
    with m_col1:
        st.metric(label="Risk Score", value=f"{report.total_risk_score} / 100")
    with m_col2:
        st.metric(label="Risk Classification", value=report.risk_classification)
    with m_col3:
        flagged_count = sum(1 for c in checks if c.detected and c.points > 0)
        st.metric(label="Triggered Indicators", value=f"{flagged_count} of {len(checks)} checks")

    # Hero Risk Scorecard with progress bar and badge
    render_risk_score_hero(report)

    # Security Recommendation Card
    st.markdown(
        f"""
        <div class="cyber-card" style="border-left: 4px solid {report.badge_color}; margin-top: 1rem;">
            <div style="font-weight: 700; color: #F8FAFC; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
                <span>🛡️ Security Recommendation</span>
            </div>
            <p style="color: #CBD5E1; font-size: 0.95rem; margin: 0; line-height: 1.5;">
                {html.escape(report.recommendation)}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 7 Detection Check Cards in Responsive 2-Column Grid
    st.markdown("---")
    st.markdown("#### 🔬 Detailed Detection Engine Breakdown (7 Security Checks)")
    check_left, check_right = st.columns(2)
    for idx, check in enumerate(checks):
        target_col = check_left if idx % 2 == 0 else check_right
        with target_col:
            render_check_card(check)

    # URL Structural Components Breakdown Table
    st.markdown("---")
    st.markdown("#### 🧩 URL Structural Components Breakdown")
    breakdown_data = {
        "Component": [
            "Effective Protocol",
            "Explicit Scheme Provided",
            "Hostname (Normalized)",
            "ASCII / IDN Hostname",
            "Apex Domain",
            "Subdomain Hierarchy",
            "Subdomain Labels Count",
            "Port Number",
            "Path",
            "Query String",
            "Fragment",
            "Host Type",
            "Sanitized Storage Representation",
        ],
        "Extracted Value": [
            parsed.effective_scheme,
            "Yes" if parsed.has_explicit_scheme else "No (Assumed for parsing)",
            parsed.hostname,
            parsed.ascii_hostname,
            parsed.domain if parsed.domain else "(none)",
            parsed.subdomain if parsed.subdomain else "(none)",
            str(len(parsed.subdomain_labels)),
            str(parsed.port) if parsed.port is not None else "(default)",
            parsed.path if parsed.path else "/",
            "[REDACTED FOR PRIVACY]" if parsed.query else "(none)",
            "[REDACTED FOR PRIVACY]" if parsed.fragment else "(none)",
            (f"IP Address (IPv{parsed.ip_version})" if parsed.ip_version else "IP Address") if parsed.is_ip else ("IDN Domain" if parsed.is_idn else "Standard Domain"),
            parsed.sanitized_url,
        ],
    }
    st.table(pd.DataFrame(breakdown_data))


# ============================================================================
# 9. Page 3: Analytics & Trends Dashboard
# ============================================================================
def apply_cyber_theme(fig: go.Figure, title: str = "") -> go.Figure:
    """Applies URL Guard dark navy/cyan cybersecurity theme to a Plotly figure."""
    fig.update_layout(
        title={
            "text": title,
            "font": {"size": 15, "color": "#F8FAFC", "family": "Segoe UI, -apple-system, sans-serif"},
            "x": 0.02,
            "xanchor": "left",
        },
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#94A3B8", "family": "Segoe UI, -apple-system, sans-serif", "size": 12},
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "xanchor": "right",
            "x": 1,
            "font": {"color": "#CBD5E1"},
        },
        margin={"l": 30, "r": 20, "t": 55 if title else 25, "b": 30},
        hoverlabel={
            "bgcolor": "#1E293B",
            "font_size": 12,
            "font_color": "#F8FAFC",
            "bordercolor": "#06B6D4",
        },
    )
    fig.update_xaxes(
        showgrid=True,
        gridwidth=1,
        gridcolor="#1E293B",
        zeroline=False,
        tickfont={"color": "#94A3B8"},
    )
    fig.update_yaxes(
        showgrid=True,
        gridwidth=1,
        gridcolor="#1E293B",
        zeroline=False,
        tickfont={"color": "#94A3B8"},
    )
    return fig


def render_analytics_page() -> None:
    """Renders Page 3: Risk Analytics & Threat Trends dashboard."""
    render_header()

    st.markdown("### 📈 Risk Analytics & Historical Threat Trends")
    st.markdown(
        "Real-time telemetry, threat classification distribution, 7-day velocity trends, and host reputation intelligence."
    )

    # Cross-Navigation Shortcuts
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("🔍 Scan New URL", key="btn_nav_home_from_analytics", use_container_width=True):
            st.session_state["current_page"] = PAGE_HOME
            st.rerun()
    with col_b:
        if st.button("📜 View Raw History", key="btn_nav_hist_from_analytics", use_container_width=True):
            st.session_state["current_page"] = PAGE_HISTORY
            st.rerun()
    with col_c:
        if st.button("🔄 Refresh Telemetry", key="btn_refresh_analytics", use_container_width=True):
            st.rerun()

    # Load and clean records
    raw_history = get_history()
    cleaned_all = clean_history_records(raw_history)

    # Empty State Guard
    if not cleaned_all:
        st.info("ℹ️ No scan history records found yet. Start inspecting URLs on the Home Dashboard to generate threat analytics and historical trends.")
        st.markdown(
            """
            <div class="cyber-card" style="text-align: center; padding: 2.5rem 1.5rem; margin-top: 1rem;">
                <span style="font-size: 3rem;">📊</span>
                <div style="font-size: 1.3rem; font-weight: 700; color: #38BDF8; margin-top: 10px;">
                    Analytics Engine Standing By
                </div>
                <p style="color: #94A3B8; max-width: 550px; margin: 10px auto 0 auto; font-size: 0.95rem; line-height: 1.5;">
                    Once URLs are scanned, URL Guard automatically aggregates threat scores, categorizes risk severity,
                    and computes continuous 7-day velocity and 24-hour diurnal inspection cycles.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Time Window Filter Selector
    st.markdown("#### ⏱️ Select Time Horizon Filter")
    selected_window = st.radio(
        "Time Horizon",
        TIME_FILTERS,
        index=1,
        horizontal=True,
        key="analytics_window_selector",
        help="Filter metrics and trends by Today, Last 7 Days, or All Time.",
    )

    # Filter records by window
    window_records = filter_history_by_window(cleaned_all, window=selected_window)
    metrics = compute_metrics(window_records)

    if len(window_records) == 0:
        st.warning(
            f"⚠️ No scans recorded for **{selected_window}**. "
            f"(Found {len(cleaned_all)} total scan(s) in All Time)."
        )

    # 6 KPI Cyber Cards
    st.markdown(f"#### 🎯 Key Security Metrics — {selected_window}")
    kpi1, kpi2, kpi3 = st.columns(3)
    with kpi1:
        st.metric(
            label="Total URLs Scanned",
            value=f"{metrics.total_scans}",
            help=f"{metrics.unique_domains_count} unique hostnames evaluated",
        )
    with kpi2:
        st.metric(
            label="High-Risk Detection Rate",
            value=f"{metrics.high_risk_rate}%",
            delta=f"{metrics.high_risk_count} dangerous URLs" if metrics.high_risk_count > 0 else "0 dangerous",
            delta_color="inverse" if metrics.high_risk_count > 0 else "normal",
            help="Percentage of scanned URLs classified as HIGH RISK (score > 50)",
        )
    with kpi3:
        st.metric(
            label="Average Risk Score",
            value=f"{metrics.avg_risk_score} / 100",
            delta=f"Peak: {metrics.max_risk_score}" if metrics.total_scans > 0 else None,
            delta_color="off",
            help="Mean heuristic risk score across scanned links in selected window",
        )

    tier1, tier2, tier3 = st.columns(3)
    with tier1:
        st.metric(
            label="🟢 Low Risk (Safe)",
            value=f"{metrics.low_risk_count} ({metrics.low_risk_pct}%)",
            help="Score 0 - 20: Minimal or no suspicious indicators detected",
        )
    with tier2:
        st.metric(
            label="🟡 Medium Risk (Suspicious)",
            value=f"{metrics.medium_risk_count} ({metrics.medium_risk_pct}%)",
            help="Score 21 - 50: Moderate structural indicators detected",
        )
    with tier3:
        st.metric(
            label="🔴 High Risk (Dangerous)",
            value=f"{metrics.high_risk_count} ({metrics.high_risk_pct}%)",
            help="Score 51 - 100: Multiple severe phishing heuristics triggered",
        )

    st.markdown("---")
    st.markdown("#### 📊 Threat Telemetry & Velocity Visualizations")

    # Chart 1: Daily Trend Stacked Bar Chart
    df_trend = get_daily_trend_data(cleaned_all, days=7)
    fig_trend = go.Figure()
    fig_trend.add_trace(go.Bar(
        x=df_trend["date"],
        y=df_trend[RISK_LOW],
        name="Low Risk",
        marker_color="#10B981",
    ))
    fig_trend.add_trace(go.Bar(
        x=df_trend["date"],
        y=df_trend[RISK_MEDIUM],
        name="Medium Risk",
        marker_color="#F59E0B",
    ))
    fig_trend.add_trace(go.Bar(
        x=df_trend["date"],
        y=df_trend[RISK_HIGH],
        name="High Risk",
        marker_color="#EF4444",
    ))
    fig_trend.update_layout(barmode="stack")
    apply_cyber_theme(fig_trend, "Daily Scan Velocity & Threat Breakdown (Past 7 Days)")

    # Chart 2: Threat Classification Donut Chart
    if metrics.total_scans > 0:
        labels = ["Low Risk", "Medium Risk", "High Risk"]
        values = [metrics.low_risk_count, metrics.medium_risk_count, metrics.high_risk_count]
        colors = ["#10B981", "#F59E0B", "#EF4444"]
        fig_donut = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.62,
                marker=dict(colors=colors, line=dict(color="#0B1120", width=2)),
                textinfo="percent+label",
                insidetextfont=dict(color="#FFFFFF", size=11),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Proportion: %{percent}<extra></extra>",
            )
        ])
        fig_donut.add_annotation(
            text=f"<b>{metrics.total_scans}</b><br><span style='font-size:10px;color:#94A3B8'>TOTAL SCANS</span>",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=14, color="#F8FAFC", family="Segoe UI, sans-serif"),
        )
    else:
        fig_donut = go.Figure()
        fig_donut.add_annotation(
            text="No scans in selected window",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=13, color="#94A3B8"),
        )
    apply_cyber_theme(fig_donut, f"Threat Tier Distribution ({selected_window})")

    # Render Row 1 Charts
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(fig_trend, use_container_width=True)
    with c2:
        st.plotly_chart(fig_donut, use_container_width=True)

    # Chart 3: Top Hostnames Horizontal Bar Chart
    active_dataset = window_records if len(window_records) > 0 else cleaned_all
    df_hosts = get_top_hostnames_data(active_dataset, top_n=8)
    if not df_hosts.empty:
        color_map = {
            RISK_LOW: "#10B981",
            RISK_MEDIUM: "#F59E0B",
            RISK_HIGH: "#EF4444",
        }
        bar_colors = [color_map.get(c, "#38BDF8") for c in df_hosts["risk_classification"]]
        fig_hosts = go.Figure(go.Bar(
            x=df_hosts["scans"],
            y=df_hosts["hostname"],
            orientation="h",
            marker_color=bar_colors,
            hovertemplate="<b>%{y}</b><br>Scans: %{x}<extra></extra>",
        ))
        fig_hosts.update_layout(yaxis=dict(autorange="reversed"))
        apply_cyber_theme(fig_hosts, "Top Evaluated Hostnames (by Volume)")
    else:
        fig_hosts = go.Figure()
        fig_hosts.add_annotation(
            text="No hostname data",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=13, color="#94A3B8"),
        )
        apply_cyber_theme(fig_hosts, "Top Evaluated Hostnames")

    # Chart 4: 24-Hour Diurnal Scan Activity Distribution
    df_hourly = get_hourly_distribution_data(active_dataset)
    fig_hourly = go.Figure(go.Bar(
        x=df_hourly["hour_label"],
        y=df_hourly["count"],
        marker_color="#06B6D4",
        hovertemplate="<b>%{x} UTC</b><br>Inspections: %{y}<extra></extra>",
    ))
    apply_cyber_theme(fig_hourly, "24-Hour Diurnal Scan Distribution (UTC)")

    # Render Row 2 Charts
    c3, c4 = st.columns(2)
    with c3:
        st.plotly_chart(fig_hosts, use_container_width=True)
    with c4:
        st.plotly_chart(fig_hourly, use_container_width=True)

    # Host Intelligence Detail Table
    if not df_hosts.empty:
        st.markdown("#### 🌐 Host Reputation & Velocity Intelligence")
        rename_hosts = {
            "hostname": "Hostname",
            "scans": "Total Inspections",
            "avg_score": "Average Risk Score",
            "max_score": "Peak Risk Score",
            "risk_classification": "Highest Severity Observed",
        }
        st.dataframe(df_hosts.rename(columns=rename_hosts), use_container_width=True)


# ============================================================================
# 10. Page 4: Scan History
# ============================================================================
def render_history_page() -> None:
    """Renders Page 3: Scan History with table, clear option, and CSV download."""
    render_header()

    st.markdown("### 📜 Local Scan History")
    st.markdown("All inspections are logged locally with query parameters and credentials securely redacted for privacy.")

    history: List[Dict[str, Any]] = get_history()

    if not history:
        st.info("ℹ️ No scan history found. Previous scans will be logged here automatically.")
    else:
        df = pd.DataFrame(history)
        for col in df.columns:
            df[col] = df[col].astype(str).str.lstrip("'")

        rename_map = {
            "scan_date_time": "Timestamp (UTC)",
            "hostname": "Hostname",
            "risk_score": "Risk Score",
            "risk_classification": "Classification",
        }
        df_display = df[::-1].rename(columns=rename_map)
        st.dataframe(df_display, use_container_width=True)

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📈 View Analytics", key="btn_view_analytics_from_hist", use_container_width=True):
                st.session_state["current_page"] = PAGE_ANALYTICS
                st.rerun()
        with col2:
            if st.button("🗑️ Clear History", key="btn_clear_hist", use_container_width=True):
                clear_history()
                st.rerun()
        with col3:
            csv_data = export_history_csv()
            st.download_button(
                label="📥 Download CSV Export",
                data=csv_data,
                file_name="url_guard_scan_history.csv",
                mime="text/csv",
                key="btn_download_hist",
                use_container_width=True,
            )


# ============================================================================
# 11. Page 5: About Project (College Evaluation & Viva Guide)
# ============================================================================
def render_about_page() -> None:
    """Renders Page 5: About Project containing academic evaluation walkthrough."""
    render_header()

    st.markdown("### 🎓 Academic College Evaluation Guide & Technical Overview")
    st.markdown(
        "A comprehensive summary of the architecture, design principles, detection rules, "
        "and security guarantees implemented in URL Guard."
    )

    with st.expander("📌 1. Project Overview & Problem Statement", expanded=True):
        st.markdown(
            """
            **Problem Statement:**  
            Phishing attacks frequently employ deceptive hyperlinks designed to impersonate legitimate organizations, 
            tricking users into revealing sensitive credentials, OTPs, and banking data. Everyday internet users struggle 
            to identify structural anomalies embedded within complex URLs.

            **Project Purpose:**  
            URL Guard is an educational and practical cybersecurity tool built to parse, inspect, and evaluate website links 
            using rule-based heuristic analysis. It calculates a transparent risk score (0 to 100) and provides clear 
            actionable guidance before visiting unknown destinations.
            """
        )

    with st.expander("🎯 2. Core Objectives & Heuristic Methodology", expanded=True):
        st.markdown(
            """
            - **Input Validation:** Reject malformed URLs, control characters, and unsupported URI schemes (e.g. `javascript:`, `file:`).
            - **Structural Parsing:** Decompose URLs into schemes, hostnames, domains, subdomains, ports, paths, queries, and fragments using standard Python modules.
            - **Suspicious Pattern Detection:** Evaluate 7 distinct heuristic indicators commonly exploited in phishing campaigns.
            - **Deterministic Scoring:** Aggregate weighted risk points, enforce a strict cap of 100, and categorize into Low, Medium, and High Risk tiers.
            - **Privacy Preservation:** Neutralize CSV formula injections and strip all query parameters, fragments, and credentials before persistent logging.
            """
        )

    with st.expander("💻 3. Technology Stack & Zero-API Architecture", expanded=True):
        st.markdown(
            """
            URL Guard is intentionally lightweight, offline-first, and maintainable. It deliberately avoids paid APIs, 
            external HTTP requests, and machine learning dependencies:

            - **Core Language:** Python 3.10+
            - **Web Framework:** Streamlit
            - **Standard Library Modules:**
              - `urllib.parse` — RFC 3986 URL decomposition and normalization
              - `ipaddress` — Hostname IPv4 and IPv6 detection and validation
              - `re` — Regular expression keyword pattern matching
              - `csv` — Local scan persistence and export
              - `datetime` — UTC timestamp generation
              - `pathlib` — Cross-platform filesystem path management
            - **Automated Testing:** Pytest suite with Streamlit `AppTest` headless verification
            """
        )

    with st.expander("🔬 4. Detection Engine Walkthrough (7 Heuristic Rules)", expanded=True):
        st.markdown(
            "The detection engine evaluates 7 independent structural rules. No single rule is counted more than once:"
        )
        rules_table_data = {
            "Rule #": ["Check 1", "Check 2", "Check 3", "Check 4", "Check 5", "Check 6", "Check 7"],
            "Detection Check": [
                "HTTPS Protocol",
                "URL Length Analysis",
                "IP Address Hostname",
                "Suspicious Keywords",
                "Special Characters / Authority @",
                "Excessive Hostname Hyphens",
                "Subdomain Complexity",
            ],
            "Condition": [
                "Explicitly uses HTTP instead of HTTPS",
                "Total URL length > 75 characters",
                "Hostname is an IPv4 or IPv6 address",
                "Contains sensitive keywords (login, bank, etc.)",
                "Deceptive @ userinfo embedded in authority",
                "Hostname contains 3 or more hyphens",
                "Hostname contains > 3 subdomain labels",
            ],
            "Points": ["+10 pts", "+10 pts", "+25 pts", "+15 pts", "+15 pts", "+10 pts", "+15 pts"],
            "Security Rationale": [
                "Unencrypted transmission; prone to interception",
                "Excessive length conceals actual destination",
                "Bypasses DNS reputation vetting and domain controls",
                "Social engineering lure imitating account portals",
                "Misleads users on true destination host authority",
                "Brand spoofing (e.g. paypal-verify-account-update)",
                "Deep hierarchy disguising fraudulent apex domain",
            ],
        }
        st.table(pd.DataFrame(rules_table_data))

    with st.expander("⚖️ 5. Risk Scoring Model & Thresholds", expanded=False):
        st.markdown(
            """
            | Score Range | Classification | Indicator Color | System Recommendation |
            |---|---|---|---|
            | **0 – 20** | **LOW RISK** | `#10B981` (Emerald) | No major suspicious characteristics detected. Standard caution advised. |
            | **21 – 50** | **MEDIUM RISK** | `#F59E0B` (Amber) | Some suspicious indicators detected. Verify domain before submitting details. |
            | **51 – 100** | **HIGH RISK** | `#EF4444` (Crimson) | Multiple suspicious characteristics identified. Avoid submitting sensitive info. |

            *Important Note:* The score is a heuristic aggregation of suspicious traits, **not** a mathematical percentage probability of compromise.
            """
        )

    with st.expander("🛡️ 6. Security, Privacy & Safety Guarantees", expanded=False):
        st.markdown(
            """
            - **No Outbound Network Traffic:** Submitted links are analysed offline. No sockets, HTTP requests, or DNS queries are generated.
            - **XSS Immunity:** Raw URLs are displayed exclusively using `st.code` and all dynamic text is escaped via `html.escape`.
            - **Credential & Query Redaction:** Query parameters (e.g. `?token=...`), fragments (`#...`), and embedded credentials (`user:pass@`) are stripped prior to CSV persistence.
            - **CSV Formula Injection Mitigation:** Neutralizes formula characters (`=`, `+`, `-`, `@`, `\\t`, `\\r`) preventing malicious execution when opened in Microsoft Excel.
            """
        )

    with st.expander("⚠️ 7. System Limitations & Future Scope", expanded=False):
        st.markdown(
            """
            **Current Limitations:**
            - Performs static structural syntax inspection only; cannot evaluate web page content or server SSL certificates.
            - Uses a rule-based 2-part ccTLD heuristic rather than querying the full live IANA Public Suffix List.
            - A Low Risk rating does not constitute a security guarantee.

            **Future Enhancements:**
            - Supervised machine learning classification trained on verified phishing datasets.
            - Real-time WHOIS domain age inspection and DNSSEC validation.
            - Community blocklist synchronization and TLS certificate transparency logging.
            """
        )

    with st.expander("👥 8. Team Contribution Section", expanded=False):
        st.markdown(
            """
            *College Project Team Contribution:*
            - **Team Member 1:** System Architecture, Input Validation & Component Parsing (`core/validator.py`, `core/parser.py`)
            - **Team Member 2:** Detection Engine Implementation & Heuristic Rules (`core/detector.py`, `core/risk_calculator.py`)
            - **Team Member 3:** Report Generation, Local Persistence & CSV Security (`core/report_generator.py`, `storage/history_manager.py`)
            - **Team Member 4:** Streamlit UI Dashboard, Cybersecurity Styling & Automated Testing (`app.py`, `tests/test_ui_smoke.py`)
            """
        )


# ============================================================================
# 11. Application Controller & Main Routing
# ============================================================================
def main() -> None:
    """Main Streamlit application entry point."""
    init_session_state()

    # Inject Dark Navy Theme CSS
    st.markdown(CYBER_CSS, unsafe_allow_html=True)

    # Sidebar Header & Branding
    st.sidebar.markdown(
        """
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 1.5rem; padding-bottom: 0.75rem; border-bottom: 1px solid #1E293B;">
            <span style="font-size: 1.8rem;">🛡️</span>
            <div>
                <div style="font-weight: 800; font-size: 1.25rem; color: #38BDF8; letter-spacing: -0.02em;">URL GUARD</div>
                <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em;">Phishing Detection</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Navigation Radio without key collision
    current_idx = PAGES.index(st.session_state["current_page"])
    selected_nav = st.sidebar.radio("Navigation", PAGES, index=current_idx)
    if selected_nav != st.session_state["current_page"]:
        st.session_state["current_page"] = selected_nav
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div style="font-size: 0.8rem; color: #64748B; line-height: 1.5;">
            <p style="margin: 0 0 4px 0;"><strong>System Status:</strong> <span style="color: #10B981;">● Engine Active</span></p>
            <p style="margin: 0 0 4px 0;"><strong>Mode:</strong> Offline Heuristic</p>
            <p style="margin: 0;"><strong>Security:</strong> Zero External API Calls</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Route to Selected Page
    if st.session_state["current_page"] == PAGE_HOME:
        render_home_page()
    elif st.session_state["current_page"] == PAGE_RESULTS:
        render_results_page()
    elif st.session_state["current_page"] == PAGE_ANALYTICS:
        render_analytics_page()
    elif st.session_state["current_page"] == PAGE_HISTORY:
        render_history_page()
    elif st.session_state["current_page"] == PAGE_ABOUT:
        render_about_page()


if __name__ == "__main__":
    main()
