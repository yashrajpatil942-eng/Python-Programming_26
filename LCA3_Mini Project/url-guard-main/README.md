# URL GUARD — URL Checker & Phishing Detection System

> **Analyse. Detect. Stay Aware.**

A modular, lightweight, and offline cybersecurity utility built in Python and Streamlit to inspect, dissect, and evaluate web links for deceptive patterns and phishing indicators.

---

## Table of Contents
1. [Project Title](#1-project-title)
2. [Project Description](#2-project-description)
3. [Problem Statement](#3-problem-statement)
4. [Main Objectives](#4-main-objectives)
5. [Features](#5-features)
6. [Technologies Used](#6-technologies-used)
7. [System Architecture](#7-system-architecture)
8. [Folder Structure](#8-folder-structure)
9. [Installation Instructions](#9-installation-instructions)
10. [How to Run Application](#10-how-to-run-application)
11. [How to Execute Tests](#11-how-to-execute-tests)
12. [UI Mockups & Example Screens](#12-ui-mockups--example-screens)
13. [Risk Scoring Methodology](#13-risk-scoring-methodology)
14. [Limitations](#14-limitations)
15. [Future Scope](#15-future-scope)
16. [Team Contributions](#16-team-contributions)

---

## 1. Project Title
**URL GUARD — URL Checker & Phishing Detection System**  
*College Engineering Mini-Project — Computer Science & Cybersecurity*

---

## 2. Project Description
**URL Guard** is an educational, privacy-preserving cybersecurity application designed to analyze arbitrary Uniform Resource Locators (URLs) for common characteristics associated with phishing, credential harvesting, and social engineering attacks. 

Unlike opaque machine learning models or remote cloud scanners that transmit sensitive browsing data across third-party APIs, URL Guard performs **100% offline, deterministic, rule-based structural inspections** using Python's standard library. It parses the URL into its constituent components (scheme, authority, hostname, port, path, query, fragment), evaluates them against seven rigorous heuristic detection rules, calculates a normalized risk score from 0 to 100, and presents actionable recommendations through an interactive Streamlit web dashboard.

---

## 3. Problem Statement
Phishing continues to be the dominant initial access vector in modern cyberattacks. Attackers craft deceptive hyperlinks that disguise fraudulent destinations as legitimate organizations, leading unsuspecting victims to fake portals where:
- Account passwords and login credentials are stolen
- Credit card numbers and banking data are harvested
- One-Time Passwords (OTPs) and session tokens are intercepted
- Malicious payload executables are delivered

Ordinary internet users often find it difficult to discern subtle URL anomalies, such as:
- Using raw IP addresses (e.g., `http://192.168.1.1/login`) instead of legitimate registered domains.
- Masking target domains using embedded user credentials and the `@` symbol (e.g., `http://paypal.com@attacker-site.com/`).
- Excessive hyphenation designed to simulate legitimate brand names (e.g., `secure-login-account-update.com`).
- Deep subdomain chaining (e.g., `bank.login.portal.verify.suspicious-host.net`).
- Transmitting sensitive credentials over unencrypted plaintext HTTP protocols.

**URL Guard** bridges this gap by providing an accessible tool that breaks down URL structures, highlights red flags, and educates users on link safety before they click.

---

## 4. Main Objectives
1. **Input Validation & Sanitization**: Safely accept arbitrary URL strings, handling schemeless inputs, malformed characters, internationalized domain names (IDN), and IPv4/IPv6 addresses without crashing.
2. **Component Decomposition**: Accurately extract all RFC-compliant URL segments using standard parsing techniques.
3. **Multi-Heuristic Inspection**: Execute seven independent detection checks covering protocol security, URL length, IP hostnames, keyword triggers, deceptive authority symbols, hyphenation, and subdomain depth.
4. **Transparent Risk Scoring**: Calculate a cumulative risk score (0 to 100) and categorize findings into Low, Medium, and High risk classifications.
5. **Actionable Visual Reporting**: Present comprehensive, jargon-free security findings with color-coded risk cards and clear browsing advice.
6. **Privacy-Preserving Audit Trail**: Maintain an optional, local CSV scan history that redacts sensitive parameters, query strings, and credentials.
7. **Educational Value**: Provide computer science students and evaluators with a transparent, easily explainable software architecture.

---

## 5. Features

### Core Analysis Capabilities
- **Safe Text-Only Analysis**: URLs are inspected purely as strings. No network requests, socket connections, or DNS queries are initiated. The application never accesses the target host or executes remote code.
- **Protocol Safety Assessment**: Detects unencrypted `http://` links versus secure `https://` links, and alerts when schemes are omitted.
- **Length Analysis**: Identifies excessively long URLs (> 75 characters) often used to obscure malicious domains on mobile screens.
- **Direct IP Address Detection**: Detects dotted IPv4 addresses and bracketed IPv6 hostnames using Python's `ipaddress` library.
- **Suspicious Keyword Matching**: Scans for 13 common phishing keywords (`login`, `verify`, `account`, `secure`, `banking`, `password`, `update`, `confirm`, `wallet`, `signin`, `support`, `bonus`, `free`) with substring boundary protection.
- **Deceptive Authority Symbol (`@`) Detection**: Differentiates between harmless `@` symbols in query parameters and dangerous user-info prefixes in the URL authority section used to mislead users.
- **Hostname Hyphen Analysis**: Flags hostnames containing 3 or more hyphens commonly employed in typosquatting and brand spoofing.
- **Subdomain Depth Analysis**: Evaluates hostname label complexity, accounting for common two-part country-code top-level domains (e.g., `.co.uk`, `.com.au`, `.edu.in`).

### User Interface & Experience
- **Interactive Multi-Page Streamlit App (5 Dedicated Pages)**:
  - **Page 1 (Home / Dashboard)**: Clean input box, quick demonstration preset sample URL buttons, instant analysis button, and security disclaimer.
  - **Page 2 (Analysis Results)**: High-impact score metric hero, color-coded risk level badge, visual progress gauge, security recommendation, 7 detailed check evidence cards, and RFC component breakdown table.
  - **Page 3 (Analytics & Trends Dashboard)**: Historical threat telemetry and risk visualization:
    - **Time Horizon Filter**: Dynamically filter statistics across **Today**, **Last 7 Days (Week)**, and **All Time**.
    - **6 Cyber KPI Metric Cards**: Total Scans, High-Risk Detection Rate %, Average Risk Score, and Low/Medium/High Risk counts & percentages.
    - **Interactive Plotly Cyber Visualizations**:
      - 7-day daily scan velocity and threat proportion stacked bar chart (zero-filled continuous time series).
      - Threat classification distribution donut chart with Emerald (`#10B981`), Amber (`#F59E0B`), and Crimson (`#EF4444`).
      - Top evaluated and riskiest hostnames horizontal bar chart and intelligence ranking table.
      - 24-hour diurnal scan activity distribution (UTC hours 00:00 to 23:00).
    - **Defensive State Handling**: Graceful empty-state graphics when no scan history exists or when the filtered horizon has 0 scans.
    - **Seamless Cross-Navigation**: Direct jump shortcuts between Home, Results, Analytics, and History.
  - **Page 4 (Scan History)**: Tabular audit log of past scans (most recent first), formula-injection-stripped display, clear history option, and local CSV download export.
  - **Page 5 (About Project)**: Project overview, academic college evaluation walkthrough, technical specifications, detection rule table, security guarantees, limitations, and team credits.
- **Cybersecurity Dark Aesthetic**: Deep navy theme (`#0B1120`, `#1E293B`) paired with high-contrast cyan accents (`#06B6D4`, `#38BDF8`), hover glow borders, styled metric cards (`[data-testid="stMetric"]`), and dark expander panels.

---

## 6. Technologies Used

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| **Language** | Python | 3.10+ | Core programming and business logic |
| **Frontend Framework** | Streamlit | >= 1.30.0 | Reactive interactive dashboard and UI components |
| **Visualizations** | Plotly | >= 6.0.0 | Cyber-themed interactive charts (donut, stacked bar, horizontal bar) |
| **Data Aggregation** | Pandas | >= 2.0.0 | Telemetry dataframe manipulation, time grouping, zero-filling |
| **URL Parsing** | `urllib.parse` | Standard Library | RFC 3986 URL splitting and unquoting |
| **IP Address Analysis** | `ipaddress` | Standard Library | Robust IPv4 / IPv6 parsing and classification |
| **Pattern Matching** | `re` | Standard Library | Regular expressions for keyword and character heuristics |
| **Data Persistence** | `csv` & `pathlib` | Standard Library | Safe local file I/O for scan history with DDE defense |
| **Data Structures** | `dataclasses` & `enum` | Standard Library | Strongly typed domain models and result contracts |
| **Testing** | Pytest | >= 7.0.0 | Automated unit, boundary, scenario, headless UI, and E2E testing |

---

## 7. System Architecture

URL Guard follows a strictly decoupled, modular pipeline architecture:

```
                      +-----------------------------+
                      |         User Input          |
                      |    (Paste / Enter URL)      |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |     core/validator.py       |
                      |  - Empty / Whitespace check |
                      |  - Length limit (<= 4096)   |
                      |  - Scheme normalization     |
                      |  - Port boundary validation |
                      +--------------+--------------+
                                     | Validated URL
                                     v
                      +-----------------------------+
                      |       core/parser.py        |
                      |  - Extract scheme, netloc   |
                      |  - IDN Punycode decoding    |
                      |  - Clean IPv6 & strip dots  |
                      |  - Subdomain label parsing  |
                      |  - Credentials isolation    |
                      +--------------+--------------+
                                     | ParsedURL Object
                                     v
                      +-----------------------------+
                      |      core/detector.py       |
                      |  - Check 1: HTTPS (+10)     |
                      |  - Check 2: Length > 75 (+10)|
                      |  - Check 3: IP Host (+25)   |
                      |  - Check 4: Keywords (+15)  |
                      |  - Check 5: Deceptive @ (+15)|
                      |  - Check 6: Hyphens >= 3 (+10)|
                      |  - Check 7: Subdomains > 3(+15)|
                      +--------------+--------------+
                                     | List[CheckResult]
                                     v
                      +-----------------------------+
                      |   core/risk_calculator.py   |
                      |  - Sum detected points      |
                      |  - Clamp max score at 100   |
                      |  - Classify: LOW / MED / HIGH|
                      |  - Generate recommendations |
                      +--------------+--------------+
                                     | RiskScoreResult
                                     v
                      +-----------------------------+
                      |  core/report_generator.py   |
                      |  - Compile 14-field report  |
                      |  - Prepare display strings  |
                      |  - Redact sensitive data    |
                      +-------+--------------+------+
                              |              |
           AnalysisReport     |              | AnalysisReport
                              v              v
      +-------------------------+          +-------------------------+
      |  storage/history_manager|          |         app.py          |
      |  - Append to CSV file   |          |  - Render Home Page     |
      |  - Redact queries/auth  |          |  - Render Results Cards |
      |  - Clear & Export CSV   |          |  - Render Analytics     |
      |  - Data: scan_history   |          |  - Render History Table |
      +------------+------------+          |  - Render About Page    |
                   |                       +------------+------------+
                   | Raw History                        ^
                   v                                    | Cleaned KPIs
      +-------------------------+                       | & DataFrames
      |    core/analytics.py    |-----------------------+
      |  - Formula quote strip  |
      |  - Window filtering     |
      |  - 7-day velocity series|
      |  - Diurnal distribution|
      |  - Domain intelligence  |
      +-------------------------+
```

---

## 8. Folder Structure

```
URL-GUARD/
├── .gitignore                  # Git exclusion rules (caches, venvs, scan CSV)
├── LICENSE                     # MIT Open Source License (2026)
├── README.md                   # Comprehensive project documentation
├── requirements.txt            # Minimal dependencies (streamlit, pytest)
├── app.py                      # Streamlit frontend & multi-page navigation
│
├── core/                       # Core analysis engine (zero external dependencies)
│   ├── __init__.py             # Core package initialization
│   ├── validator.py            # Input validation, scheme normalizer, port checker
│   ├── parser.py               # RFC component parser, IDN, IPv4/v6 normalizer
│   ├── detector.py             # 7 independent heuristic detection rules
│   ├── risk_calculator.py      # Score accumulator, cap, tier classifier
│   ├── report_generator.py     # Comprehensive structured report compiler
│   └── analytics.py            # Pure aggregation, window filtering & trends engine
│
├── storage/                    # Local data persistence
│   ├── __init__.py             # Storage package initialization
│   └── history_manager.py      # CSV scan log manager with privacy redaction & locking
│
├── data/                       # Data persistence directory
│   ├── .gitkeep                # Keeps directory structure in git tracking
│   ├── scan_history.csv        # Local CSV scan log (auto-created on first scan)
│   └── scan_history.csv.bak    # Baseline scan history backup snapshot
│
└── tests/                      # Automated test suite (354 test cases)
    ├── __init__.py             # Test package initialization
    ├── conftest.py             # Shared pytest fixtures and sys.path setup
    ├── test_validator.py       # Validator module unit & boundary tests (55 tests)
    ├── test_parser.py          # Component extraction & normalization tests (13 tests)
    ├── test_detector.py        # Independent unit tests for all 7 checks (29 tests)
    ├── test_risk_calculator.py # Score summation, boundary & capping tests (14 tests)
    ├── test_history.py         # CSV file persistence & privacy redaction tests (46 tests)
    ├── test_analytics.py       # Analytics aggregation, filtering & trends tests (24 tests)
    ├── test_ui_smoke.py        # Streamlit AppTest headless smoke tests (21 tests)
    └── test_e2e_scenarios.py   # Comprehensive end-to-end scenario tests (152 tests)
```

---

## 9. Installation Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed on your system.
- Git (optional, for cloning).

---

### Windows (PowerShell)

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd "c:\Users\Aditya Patel\Documents\URL CHECKER"
   ```

2. Create a virtual environment:
   ```powershell
   python -m venv .venv
   ```

3. Activate the virtual environment:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
   *(If execution policies block script activation, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

4. Upgrade `pip` and install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

### Linux / macOS (Bash / Zsh)

1. Open Terminal and navigate to the project directory:
   ```bash
   cd ~/path/to/URL-GUARD
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   ```

3. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```

4. Upgrade `pip` and install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 10. How to Run Application

With your virtual environment activated, run:

```bash
streamlit run app.py
```

### Accessing the Dashboard
Once launched, Streamlit will automatically open your default browser to:
- **Local URL**: `http://localhost:8501`
- **Network URL**: `http://<your-lan-ip>:8501`

### Sample Test URLs to Try
- **Clean Legitimate Link (Low Risk, Score 0)**:
  `https://www.google.com/search?q=cybersecurity`
- **Suspicious Keyword + HTTP (Medium Risk, Score 25)**:
  `http://example.com/account/login-update`
- **Deceptive @ + IP Address + Length (High Risk, Score 60+)**:
  `http://paypal.com@192.168.1.100/verify/secure-account-update-portal-authorization/`

---

## 11. How to Execute Tests

The project includes an exhaustive automated test suite with **354 tests** covering unit behavior, boundary thresholds, pairwise cross-feature interactions, analytics time-window aggregations, and end-to-end attack scenarios.

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Specific Test Modules
```bash
# Test individual components
python -m pytest tests/test_validator.py -v
python -m pytest tests/test_parser.py -v
python -m pytest tests/test_detector.py -v
python -m pytest tests/test_risk_calculator.py -v
python -m pytest tests/test_history.py -v
python -m pytest tests/test_analytics.py -v
python -m pytest tests/test_ui_smoke.py -v

# Run the 152 End-to-End Scenarios
python -m pytest tests/test_e2e_scenarios.py -v
```

### Expected Output Summary
```text
============================= test session starts =============================
platform win32 -- Python 3.13.x, pytest-9.x.x
collected 354 items

tests/test_analytics.py ........................                         [  6%]
tests/test_detector.py .............................                    [ 14%]
tests/test_e2e_scenarios.py ............................................ [ 57%]
tests/test_history.py .................................................. [ 70%]
tests/test_parser.py .............                                       [ 74%]
tests/test_risk_calculator.py ..............                             [ 78%]
tests/test_ui_smoke.py .....................                             [ 84%]
tests/test_validator.py ............................................... [100%]

============================ 354 passed in 10.71s =============================
```

---

## 12. UI Mockups & Example Screens

### Page 1: Home / Dashboard
```text
+---------------------------------------------------------------------------------+
|                                                                                 |
|                                    [ SHIELD ]                                   |
|                                    URL GUARD                                    |
|                           Analyse. Detect. Stay Aware.                          |
|                                                                                 |
|   Analyze website links for deceptive characteristics and phishing indicators   |
|   before visiting them. 100% offline, privacy-first heuristic evaluation.       |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | Enter URL to analyze (e.g., https://example.com/login)                    |  |
|  | [ http://secure-banking-verify.com.account-update.info/login             ] |  |
|  +---------------------------------------------------------------------------+  |
|                                                                                 |
|  [ SAMPLE: Clean Domain ]  [ SAMPLE: IP Address ]  [ SAMPLE: Phishing Link ]   |
|                                                                                 |
|                           [ >>> ANALYSE URL <<< ]                               |
|                                                                                 |
|  -----------------------------------------------------------------------------  |
|  [!] SAFETY NOTICE: URL Guard provides heuristic rule-based assessments.        |
|      A low-risk score indicates fewer detected suspicious indicators, but does  |
|      not guarantee that an external website is completely safe.                 |
+---------------------------------------------------------------------------------+
```

### Page 2: Analysis Results
```text
+---------------------------------------------------------------------------------+
|  <-- Back to Dashboard                                        ANALYSIS RESULTS  |
|  Target URL: http://secure-banking-verify.com.account-update.info/login         |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | [!] HIGH RISK                                     TOTAL RISK SCORE: 60/100 |  |
|  | [====================================...............................] 60%  |  |
|  | Recommendation: Multiple high-risk suspicious characteristics were        |  |
|  | identified. Do NOT enter credentials or download files from this link.     |  |
|  +---------------------------------------------------------------------------+  |
|                                                                                 |
|  DETAILED HEURISTIC BREAKDOWN:                                                  |
|                                                                                 |
|  +-------------------------------------+ +------------------------------------+ |
|  | [!] CHECK 1: Scheme Security        | | [!] CHECK 2: URL Length            | |
|  | Result: Unencrypted HTTP (+10 pts)  | | Result: Length is 58 chars (0 pts) | |
|  | Status: Plaintext transmission      | | Status: Under 75 char limit        | |
|  +-------------------------------------+ +------------------------------------+ |
|  +-------------------------------------+ +------------------------------------+ |
|  | [✓] CHECK 3: IP Address Hostname    | | [!] CHECK 4: Suspicious Keywords   | |
|  | Result: Registered Domain (0 pts)   | | Result: 'banking', 'login' (+15 pts)| |
|  | Status: Uses named domain           | | Status: Deceptive intent words     | |
|  +-------------------------------------+ +------------------------------------+ |
|  +-------------------------------------+ +------------------------------------+ |
|  | [✓] CHECK 5: Deceptive Authority @  | | [!] CHECK 6: Excessive Hyphens     | |
|  | Result: No deceptive @ symbol(0 pts)| | Result: 3 hyphens in host (+10 pts)| |
|  | Status: Clean authority field       | | Status: Potential typo-squatting   | |
|  +-------------------------------------+ +------------------------------------+ |
|  +----------------------------------------------------------------------------+ |
|  | [!] CHECK 7: Subdomain Complexity Analysis                                 | |
|  | Result: 4 subdomain labels detected (+15 pts)                              | |
|  | Status: Deep subdomain chaining disguising genuine root domain             | |
|  +----------------------------------------------------------------------------+ |
+---------------------------------------------------------------------------------+
```

### Page 3: Analytics & Trends Dashboard
```text
+---------------------------------------------------------------------------------+
|  [ 🔍 Scan New URL ]       [ 📜 View Raw History ]       [ 🔄 Refresh Telemetry ]|
|                                                                                 |
|  TIME HORIZON FILTER:  ( ) Today   (*) Last 7 Days   ( ) All Time               |
|                                                                                 |
|  +-----------------------+ +-----------------------+ +------------------------+ |
|  | TOTAL URLS SCANNED    | | HIGH-RISK DETECTION   | | AVERAGE RISK SCORE     | |
|  | 28 Scans              | | 14.3% (4 dangerous)   | | 24.8 / 100             | |
|  +-----------------------+ +-----------------------+ +------------------------+ |
|  +-----------------------+ +-----------------------+ +------------------------+ |
|  | [!] LOW RISK (SAFE)   | | [!] MEDIUM RISK       | | [!] HIGH RISK (DANGER) | |
|  | 18 (64.3%)            | | 6 (21.4%)             | | 4 (14.3%)              | |
|  +-----------------------+ +-----------------------+ +------------------------+ |
|                                                                                 |
|  DAILY SCAN VELOCITY (STACKED BAR)          THREAT CLASSIFICATION (DONUT)       |
|  [|||| Low ] [||| Med ] [|| High ]          [ 🟢 64.3% ] [ 🟡 21.4% ] [ 🔴 14.3%]|
|  Mon Tue Wed Thu Fri Sat Sun                Total Scans: 28                     |
|                                                                                 |
|  TOP EVALUATED HOSTNAMES (HORIZONTAL BAR)   24-HOUR DIURNAL ACTIVITY (UTC)      |
|  google.com    [=====================] 12   00:00 - 06:00 [==] 3                |
|  192.168.1.1   [========] 4                 06:00 - 12:00 [=======] 8           |
|  phish-portal  [====] 2                     12:00 - 18:00 [============] 13     |
|                                             18:00 - 24:00 [====] 4              |
+---------------------------------------------------------------------------------+
```

### Page 4: Scan History
```text
+---------------------------------------------------------------------------------+
|  SCAN AUDIT LOG                                          [ Download CSV Export ]|
|                                                                                 |
|  +---------------------+-------------------------------+-------+-------------+  |
|  | Timestamp (UTC)     | Target Hostname               | Score | Risk Level  |  |
|  +---------------------+-------------------------------+-------+-------------+  |
|  | 2026-11-15 15:10:22 | google.com                    | 0     | LOW RISK    |  |
|  | 2026-11-15 15:14:45 | 192.168.1.1                   | 35    | MEDIUM RISK |  |
|  | 2026-11-15 15:18:03 | secure-banking-verify.com...  | 60    | HIGH RISK   |  |
|  | 2026-11-15 15:22:11 | paypal.com.account-update.ru  | 75    | HIGH RISK   |  |
|  +---------------------+-------------------------------+-------+-------------+  |
|                                                                                 |
|  Privacy Notice: Query parameters, fragments, and credentials are automatically  |
|  redacted before being logged to the local audit store.                         |
|                                                                                 |
|  [ Clear Scan History ]                                                         |
+---------------------------------------------------------------------------------+
```

### Page 5: About Project
```text
+---------------------------------------------------------------------------------+
|  ABOUT URL GUARD                                                                |
|                                                                                 |
|  College Engineering Mini-Project                                               |
|  Department of Computer Science and Engineering                                 |
|                                                                                 |
|  * Problem Definition: Mitigating phishing attacks through structural analysis |
|  * Engineering Principles: Decoupled modular design, Python standard library   |
|  * Detection Engine: 7-rule deterministic heuristic matrix                     |
|  * UI Architecture: Modern reactive multi-page Streamlit dashboard             |
|                                                                                 |
|  SCORING MATRIX OVERVIEW:                                                       |
|  - Protocol (HTTP): +10       - Keyword Patterns: +15   - Hyphens >= 3: +10     |
|  - Length > 75:     +10       - Authority @:      +15   - Subdomains > 3: +15   |
|  - IP Hostname:     +25                                                         |
|                                                                                 |
|  Max Score: 100 points | Low: 0-20 | Medium: 21-50 | High: 51-100               |
+---------------------------------------------------------------------------------+
```

---

## 13. Risk Scoring Methodology

URL Guard employs a transparent, non-probabilistic scoring system. Each heuristic evaluates an orthogonal risk property of the submitted URL:

### Point Breakdown Matrix

| Rule # | Detection Name | Trigger Condition | Points | Rationale |
|:---:|---|---|:---:|---|
| **1** | **HTTP Protocol** | Explicit scheme is `http://` instead of `https://` | **+10** | Unencrypted communication exposes traffic to interception and tampering. *(Note: Missing scheme is flagged neutrally as +0 pts).* |
| **2** | **URL Length** | Total string length > 75 characters | **+10** | Abnormally long URLs are often crafted to push the genuine domain out of view on mobile screens. |
| **3** | **IP Hostname** | Hostname is an IPv4 or IPv6 address | **+25** | Legitimate services rarely use direct IP hostnames for public web traffic; often indicates transient attack servers. |
| **4** | **Suspicious Keywords** | URL contains targeted keywords (`login`, `verify`, `banking`, etc.) | **+15** | Phishing links frequently leverage urgency/security terms to trick victims into credential entry. Flat scoring prevents overcounting. |
| **5** | **Deceptive `@` Authority** | `@` symbol present in the URL authority/userinfo section | **+15** | Browser authority syntax allows `http://legit.com@attacker.com`, tricking users regarding the actual destination. |
| **6** | **Excessive Hyphens** | Hostname contains $\ge 3$ hyphen characters | **+10** | Attackers combine keywords with hyphens (e.g., `paypal-security-update-center.com`) to spoof recognized brands. |
| **7** | **Subdomain Complexity** | Hostname contains $> 3$ subdomain labels | **+15** | Attackers nest multiple subdomains to mimic genuine URLs while controlling only an obscure top-level domain. |

**Maximum Possible Score**: Capped strictly at **100 points**.

---

### Risk Classification Thresholds

```
   0                     20 21                     50 51                    100
   +-----------------------+------------------------+-------------------------+
   |       LOW RISK        |      MEDIUM RISK       |        HIGH RISK        |
   |      (0 - 20 pts)     |     (21 - 50 pts)      |      (51 - 100 pts)     |
   |   Color: #10B981      |    Color: #F59E0B      |     Color: #EF4444      |
   +-----------------------+------------------------+-------------------------+
```

- **LOW RISK (0 – 20 Points)**: Few or no suspicious indicators were detected. The URL appears structurally normal.
- **MEDIUM RISK (21 – 50 Points)**: Some suspicious characteristics are present. Users should carefully verify the domain identity.
- **HIGH RISK (51 – 100 Points)**: Multiple high-risk indicators were detected. Extreme caution is advised; avoid entering sensitive information.

---

### Non-Probabilistic Heuristic Disclaimer
> **MANDATORY NOTICE**:  
> The score generated by URL Guard represents a **heuristic tally of structural indicators**, **NOT** a mathematically verified probability or machine-learning confidence percentage.
> - A score of `0` does **not** guarantee that a website is safe or benevolent.
> - A high score indicates the presence of characteristics commonly observed in phishing attacks, but cannot guarantee malicious intent without external corroboration.

---

## 14. Limitations

1. **Syntactic Inspection Only**: URL Guard analyzes the URL string structure offline. It does not initiate HTTP/HTTPS handshakes, follow redirects, or inspect HTML DOM content.
2. **No Dynamic Content or JavaScript Analysis**: Phishing pages with benign URLs that deliver exploits via JavaScript or drive-by downloads cannot be detected by lexical URL inspection alone.
3. **No External Threat Feeds**: To guarantee privacy and offline operation, URL Guard does not query external threat intelligence APIs (such as VirusTotal, Google Safe Browsing, or PhishTank).
4. **Heuristic Subdomain Parsing**: While URL Guard includes recognition of two-part country-code TLDs (e.g., `.co.uk`, `.com.au`, `.edu.in`), it does not embed the full multi-megabyte Mozilla Public Suffix List.
5. **No Whois / Domain Age Lookups**: Newly registered domains (NRDs)—a frequent indicator of phishing—cannot be verified without external Whois network requests.

---

## 15. Future Scope

- **Machine Learning Classifier**: Train supervised models (e.g., Random Forest, XGBoost, or character-level CNN/LSTM) on labeled phishing corpora (such as PhishTank and Tranco) to complement rule-based heuristics.
- **Threat Intelligence API Connectors**: Optional, user-configured API integrations for Google Safe Browsing, VirusTotal, and AlienVault OTX with opt-in privacy toggles.
- **Live TLS/SSL Inspection**: Offline certificate validation and SAN (Subject Alternative Name) checking to detect mismatched SSL certificates.
- **Browser Extension**: Port the detection engine to a WebExtension (Chrome / Firefox / Edge) for real-time browsing protection.
- **Sandboxed Headless Browser Preview**: Safe screenshot rendering of submitted URLs inside a restricted Docker or WebAssembly sandbox.

---

## 16. Team Contributions

*Editable placeholder section for college evaluation and project attribution:*

| Member Name | Student ID / Roll No | Role | Key Contributions |
|---|---|---|---|
| **[Student 1 Name]** | `[Roll Number]` | Project Lead & UI/UX | Designed Streamlit dashboard, session flow, visual CSS theme, and About page documentation. |
| **[Student 2 Name]** | `[Roll Number]` | Core Engine Architect | Implemented URL validation, RFC parsing, IDN normalization, and port checking modules. |
| **[Student 3 Name]** | `[Roll Number]` | Detection & Risk Engineer | Developed 7 heuristic detection checks, scoring algorithms, and report generation logic. |
| **[Student 4 Name]** | `[Roll Number]` | QA & Persistence Engineer | Developed test suite (325 tests), CSV storage manager, privacy redaction, and packaging. |

---

## License
This project is open-source software licensed under the [MIT License](LICENSE).  
Copyright © 2026 URL Guard Contributors.
