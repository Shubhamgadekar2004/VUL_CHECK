import streamlit as st
import requests
import ssl
import socket
from urllib.parse import urlparse
import pandas as pd
from datetime import datetime
import plotly.express as px

# Set page config
st.set_page_config(
    page_title="Website Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

# Apply custom styling
st.markdown("""
<style>
    .main {
        background-color: #14171b;
    }
    .stAlert {
        border-radius: 8px;
    }
    .security-score {
        font-size: 24px;
        font-weight: bold;
        text-align: center;
        padding: 10px;
        border-radius: 8px;
        margin-bottom: 20px;
    }
    .good-score {
        background-color: #d4edda;
        color: #155724;
    }
    .medium-score {
        background-color: #fff3cd;
        color: #856404;
    }
    .bad-score {
        background-color: #f8d7da;
        color: #721c24;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar with app info
with st.sidebar:
    st.image("cyber.jpg", width=150)
    st.title("About")
    st.info(
        "This tool scans websites for common security vulnerabilities and configuration issues. "
        "Use it to identify potential security risks and get recommendations for fixes."
    )
    st.markdown("### Features")
    st.markdown("- Security Headers Analysis")
    st.markdown("- SSL/TLS Configuration Check")
    st.markdown("- Security Score Calculation")
    st.markdown("- Detailed Recommendations")
    
    st.markdown("---")
    st.caption("⚠️ For educational purposes only. Always get permission before scanning websites you don't own.")

# Main content
st.title("🛡️ Website Security Scanner")
st.markdown("Analyze your website for security vulnerabilities and get recommendations for improvement.")

# User Input
col1, col2 = st.columns([3, 1])
with col1:
    url = st.text_input("Enter website URL:", placeholder="https://example.com")
with col2:
    scan_button = st.button("🔍 Scan Website", type="primary", use_container_width=True)

# Helper functions
def is_valid_url(url):
    """Check if URL is valid."""
    if not url.startswith(('http://', 'https://')):
        return False
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_security_headers(headers):
    """Check for presence of security headers."""
    security_headers = {
        "Content-Security-Policy": {
            "importance": "High",
            "description": "Prevents XSS attacks by specifying trusted sources of content",
            "recommendation": "Add a CSP header to restrict which resources can be loaded"
        },
        "X-Frame-Options": {
            "importance": "Medium",
            "description": "Protects against clickjacking attacks",
            "recommendation": "Set to DENY or SAMEORIGIN to prevent your site from being framed"
        },
        "X-Content-Type-Options": {
            "importance": "Medium", 
            "description": "Prevents MIME type sniffing",
            "recommendation": "Set to 'nosniff' to ensure browsers respect declared content types"
        },
        "Strict-Transport-Security": {
            "importance": "High",
            "description": "Enforces HTTPS connections",
            "recommendation": "Set max-age to at least 31536000 (1 year) and include subdomains"
        },
        "Referrer-Policy": {
            "importance": "Medium",
            "description": "Controls how much referrer information is included with requests",
            "recommendation": "Set to 'no-referrer' or 'strict-origin-when-cross-origin'"
        },
        "Permissions-Policy": {
            "importance": "Medium",
            "description": "Controls browser features and APIs that can be used",
            "recommendation": "Restrict unnecessary browser features"
        },
        "X-XSS-Protection": {
            "importance": "Low", 
            "description": "Provides basic XSS protection in older browsers",
            "recommendation": "Set to '1; mode=block', although CSP is preferred"
        }
    }
    
    results = {}
    for header, info in security_headers.items():
        header_present = any(h.lower() == header.lower() for h in headers)
        results[header] = {
            "present": header_present,
            "importance": info["importance"],
            "description": info["description"],
            "recommendation": info["recommendation"]
        }
    return results

def check_ssl_security(hostname):
    """Check SSL/TLS configuration."""
    results = {
        "has_ssl": False,
        "certificate_expiry": None,
        "protocol_version": None,
        "cipher_suite": None,
        "issues": []
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                results["has_ssl"] = True
                cert = ssock.getpeercert()
                if "notAfter" in cert:
                    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    results["certificate_expiry"] = expires.strftime("%Y-%m-%d")
                    days_left = (expires - datetime.now()).days
                    if days_left < 30:
                        results["issues"].append(f"Certificate expires soon ({days_left} days)")
                
                results["protocol_version"] = ssock.version()
                if results["protocol_version"] in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    results["issues"].append(f"Outdated protocol: {results['protocol_version']}")
                
                results["cipher_suite"] = ssock.cipher()[0]
                
    except Exception as e:
        results["issues"].append(f"SSL error: {str(e)}")
    
    return results

def calculate_security_score(headers_results, ssl_results):
    """Calculate an overall security score based on findings."""
    score = 100
    
    # Security headers deductions
    header_weights = {
        "Content-Security-Policy": 10,
        "X-Frame-Options": 5,
        "X-Content-Type-Options": 5,
        "Strict-Transport-Security": 10,
        "Referrer-Policy": 5,
        "Permissions-Policy": 5,
        "X-XSS-Protection": 3
    }
    
    for header, result in headers_results.items():
        if not result["present"] and header in header_weights:
            score -= header_weights[header]
    
    # SSL/TLS deductions
    if not ssl_results["has_ssl"]:
        score -= 25
    else:
        if ssl_results["protocol_version"] in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            score -= 15
        
        if len(ssl_results["issues"]) > 0:
            score -= 5 * len(ssl_results["issues"])
    
    # Ensure score is within bounds
    return max(0, min(100, score))

def generate_recommendations(headers_results, ssl_results):
    """Generate prioritized recommendations based on scan results."""
    recommendations = []
    
    # Add header recommendations
    for header, result in headers_results.items():
        if not result["present"]:
            importance = result["importance"]
            priority = {"High": 1, "Medium": 2, "Low": 3}.get(importance, 4)
            recommendations.append({
                "category": "Headers",
                "priority": priority,
                "issue": f"Missing {header}",
                "impact": result["description"],
                "recommendation": result["recommendation"]
            })
    
    # Add SSL recommendations
    if not ssl_results["has_ssl"]:
        recommendations.append({
            "category": "SSL/TLS",
            "priority": 1,
            "issue": "No SSL/TLS detected",
            "impact": "Transmitted data is not encrypted, leading to potential data exposure",
            "recommendation": "Implement HTTPS with a valid SSL certificate"
        })
    else:
        for issue in ssl_results["issues"]:
            if "expires soon" in issue:
                recommendations.append({
                    "category": "SSL/TLS",
                    "priority": 2,
                    "issue": issue,
                    "impact": "Expired certificates cause browser warnings and security issues",
                    "recommendation": "Renew your SSL certificate before expiration"
                })
            elif "Outdated protocol" in issue:
                recommendations.append({
                    "category": "SSL/TLS",
                    "priority": 1,
                    "issue": issue,
                    "impact": "Outdated protocols have known vulnerabilities",
                    "recommendation": "Configure your server to use TLSv1.2 or TLSv1.3 only"
                })
    
    # Sort by priority
    recommendations.sort(key=lambda x: x["priority"])
    return recommendations

def get_python_implementation_examples(header_name):
    """Return Python implementation examples for security headers."""
    examples = {
        "Content-Security-Policy": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://trusted-cdn.com; style-src 'self' 'unsafe-inline' https://trusted-cdn.com; img-src 'self' data: https:;"
    return response

# Using Django
# In your middleware.py file:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://trusted-cdn.com; style-src 'self' 'unsafe-inline' https://trusted-cdn.com; img-src 'self' data: https:;"
        return response

# Using FastAPI
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://trusted-cdn.com; style-src 'self' 'unsafe-inline' https://trusted-cdn.com; img-src 'self' data: https:;"
    return response
""",
        "X-Frame-Options": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # or 'DENY'
    return response

# Using Django
# Django has built-in support for X-Frame-Options
# In settings.py:
X_FRAME_OPTIONS = 'SAMEORIGIN'  # or 'DENY'

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # or 'DENY'
    return response
""",
        "X-Content-Type-Options": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Using Django
# In your middleware.py:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Content-Type-Options'] = 'nosniff'
        return response

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
""",
        "Strict-Transport-Security": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Using Django
# In your middleware.py:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
""",
        "Referrer-Policy": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Using Django
# In your middleware.py:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
""",
        "Permissions-Policy": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(self)'
    return response

# Using Django
# In your middleware.py:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(self)'
        return response

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(self)'
    return response
""",
        "X-XSS-Protection": """
# Using Flask
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Using Django
# In your middleware.py:
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-XSS-Protection'] = '1; mode=block'
        return response

# Using FastAPI
from fastapi import FastAPI

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
"""
    }
    
    return examples.get(header_name, "Implementation example not available")

def get_python_ssl_implementation():
    """Return Python implementation example for SSL setup."""
    return """
# Using Flask with python-certbot-nginx
# 1. Install certbot
# sudo apt-get update
# sudo apt-get install certbot python3-certbot-nginx

# 2. Obtain a certificate
# sudo certbot --nginx -d example.com -d www.example.com

# 3. Configure your Flask app to use HTTPS
from flask import Flask

app = Flask(__name__)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))

# Using Django
# In settings.py:
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Using FastAPI with Uvicorn
# uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./key.pem --ssl-certfile ./cert.pem
"""

# Main scanning logic
if scan_button and url:
    if not is_valid_url(url):
        st.error("⚠️ Please enter a valid URL including http:// or https://")
    else:
        with st.spinner("Scanning website for vulnerabilities..."):
            try:
                # Extract domain for checks
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                if domain.startswith('www.'):
                    domain = domain[4:]
                
                # Get headers
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                # Initialize tabs
                overview_tab, headers_tab, ssl_tab, recommendations_tab = st.tabs([
                    "📊 Overview", 
                    "🔤 Headers", 
                    "🔒 SSL/TLS", 
                    "📝 Recommendations"
                ])
                
                # Run various checks
                headers_results = check_security_headers(response.headers)
                ssl_results = check_ssl_security(domain)
                
                # Calculate security score
                security_score = calculate_security_score(headers_results, ssl_results)
                recommendations = generate_recommendations(headers_results, ssl_results)
                
                # Overview tab
                with overview_tab:
                    st.success(f"✅ Site is accessible! Status code: {response.status_code}")
                    
                    # Security Score visualization
                    col1, col2 = st.columns([1, 2])
                    with col1:
                        score_color = "good-score" if security_score >= 80 else "medium-score" if security_score >= 50 else "bad-score"
                        st.markdown(f"""
                            <div class="security-score {score_color}">
                                Security Score: {security_score}/100
                            </div>
                        """, unsafe_allow_html=True)
                        
                        # Count issues by severity
                        high_issues = sum(1 for r in recommendations if r["priority"] == 1)
                        medium_issues = sum(1 for r in recommendations if r["priority"] == 2)
                        low_issues = sum(1 for r in recommendations if r["priority"] == 3)
                        
                        st.metric("High Priority Issues", high_issues, delta=None, delta_color="inverse")
                        st.metric("Medium Priority Issues", medium_issues, delta=None, delta_color="inverse")
                        st.metric("Low Priority Issues", low_issues, delta=None, delta_color="inverse")
                    
                    with col2:
                        # Create data for charts
                        categories = ["Headers", "SSL/TLS"]
                        issues_by_category = [
                            sum(1 for r in recommendations if r["category"] == "Headers"),
                            sum(1 for r in recommendations if r["category"] == "SSL/TLS")
                        ]
                        
                        fig = px.bar(
                            x=categories,
                            y=issues_by_category,
                            labels={"x": "Category", "y": "Issues Found"},
                            title="Issues by Category",
                            color=issues_by_category,
                            color_continuous_scale=["green", "yellow", "red"],
                        )
                        fig.update_layout(height=300)
                        st.plotly_chart(fig, use_container_width=True)
                    
                    # Summary of findings
                    st.subheader("📝 Summary of Findings")
                    cols = st.columns(2)
                    
                    with cols[0]:
                        st.markdown("#### Headers")
                        missing_count = sum(1 for h in headers_results.values() if not h["present"])
                        if missing_count == 0:
                            st.success("All important security headers are present")
                        else:
                            st.warning(f"Missing {missing_count} security headers")
                    
                    with cols[1]:
                        st.markdown("#### SSL/TLS")
                        if ssl_results["has_ssl"]:
                            if ssl_results["issues"]:
                                st.warning(f"SSL enabled with {len(ssl_results['issues'])} issues")
                            else:
                                st.success("SSL properly configured")
                        else:
                            st.error("SSL not enabled")
                
                # Security Headers tab
                with headers_tab:
                    st.subheader("🔍 Security Headers Analysis")
                    
                    # Create a dataframe for better visualization
                    headers_data = []
                    for header, result in headers_results.items():
                        status = "✅ Present" if result["present"] else "❌ Missing"
                        headers_data.append({
                            "Header": header,
                            "Status": status,
                            "Importance": result["importance"],
                            "Description": result["description"]
                        })
                    
                    df = pd.DataFrame(headers_data)
                    
                    # Color the status column
                    def highlight_status(val):
                        if "Present" in val:
                            return "background-color: #d4edda; color: #155724"
                        else:
                            return "background-color: #f8d7da; color: #721c24"
                    
                    styled_df = df.style.applymap(highlight_status, subset=["Status"])
                    st.dataframe(styled_df, use_container_width=True)
                    
                    # Raw headers
                    with st.expander("View Raw Response Headers"):
                        st.json(dict(response.headers))
                
                # SSL/TLS tab
                with ssl_tab:
                    st.subheader("🔒 SSL/TLS Configuration")
                    
                    if ssl_results["has_ssl"]:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric("Protocol Version", ssl_results["protocol_version"] or "Unknown")
                            if ssl_results["protocol_version"] in ["TLSv1.2", "TLSv1.3"]:
                                st.success("Using a secure protocol version")
                            elif ssl_results["protocol_version"]:
                                st.error(f"Using outdated protocol: {ssl_results['protocol_version']}")
                        
                        with col2:
                            st.metric("Certificate Expires", ssl_results["certificate_expiry"] or "Unknown")
                            if ssl_results["certificate_expiry"]:
                                expires = datetime.strptime(ssl_results["certificate_expiry"], "%Y-%m-%d")
                                days_left = (expires - datetime.now()).days
                                if days_left > 30:
                                    st.success(f"Certificate valid for {days_left} more days")
                                else:
                                    st.warning(f"Certificate expires in {days_left} days")
                        
                        st.metric("Cipher Suite", ssl_results["cipher_suite"] or "Unknown")
                        
                        if ssl_results["issues"]:
                            st.error("Issues Found:")
                            for issue in ssl_results["issues"]:
                                st.markdown(f"- {issue}")
                        else:
                            st.success("No SSL/TLS issues detected")
                    else:
                        st.error("❌ SSL/TLS not enabled. Your site is not using HTTPS.")
                        st.markdown("""
                            ### Why HTTPS is important:
                            - Protects data integrity
                            - Ensures user privacy
                            - Builds trust with visitors
                            - Improves SEO rankings
                            - Required for modern browser features
                        """)
                
                # Recommendations tab
                with recommendations_tab:
                    st.subheader("📝 Security Recommendations")
                    
                    if recommendations:
                        # Group recommendations by priority
                        priority_names = {1: "🔴 High Priority", 2: "🟠 Medium Priority", 3: "🟡 Low Priority"}
                        
                        for priority in [1, 2, 3]:
                            priority_recs = [r for r in recommendations if r["priority"] == priority]
                            if priority_recs:
                                with st.expander(f"{priority_names.get(priority)} ({len(priority_recs)})", expanded=(priority == 1)):
                                    for i, rec in enumerate(priority_recs):
                                        st.markdown(f"### {i+1}. {rec['issue']}")
                                        st.markdown(f"**Category:** {rec['category']}")
                                        st.markdown(f"**Impact:** {rec['impact']}")
                                        st.markdown(f"**Recommendation:** {rec['recommendation']}")
                                        
                                        # Provide code examples for common issues
                                        if rec["category"] == "Headers":
                                            header_name = rec["issue"].replace("Missing ", "")
                                            with st.expander("View Python Implementation Example"):
                                                st.code(get_python_implementation_examples(header_name))
                                        elif "SSL/TLS" in rec["category"] and "not enabled" in rec["issue"]:
                                            with st.expander("View Python SSL Implementation Example"):
                                                st.code(get_python_ssl_implementation())
                                        
                                        st.markdown("---")
                    else:
                        st.success("No recommendations needed! Your website has good security configurations.")
                    
                    # General security best practices
                    with st.expander("Additional Python Security Best Practices"):
                        st.markdown("""
                        ### Python Web Security Best Practices
                        
                        1. **Use security-focused packages**
                           ```python
                           # For secure cookies in Flask
                           app.config['SESSION_COOKIE_SECURE'] = True
                           app.config['SESSION_COOKIE_HTTPONLY'] = True
                           app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
                           
                           # For Django
                           # In settings.py
                           SECURE_BROWSER_XSS_FILTER = True
                           SECURE_CONTENT_TYPE_NOSNIFF = True
                           SECURE_HSTS_SECONDS = 31536000
                           SECURE_HSTS_INCLUDE_SUBDOMAINS = True
                           SECURE_SSL_REDIRECT = True
                           ```
                           
                        2. **Input validation and sanitization**
                           ```python
                           # Using validators library
                           import validators
                           
                           def process_url(url):
                               if not validators.url(url):
                                   return "Invalid URL"
                               # proceed with valid URL
                           
                           # Using pydantic for data validation
                           from pydantic import BaseModel, HttpUrl
                           
                           class UrlInput(BaseModel):
                               url: HttpUrl
                           ```
                           
                        3. **Protection against SQL injection**
                           ```python
                           # Using SQLAlchemy ORM instead of raw SQL
                           from sqlalchemy import select
                           from models import User
                           
                           # Safe - parameters are properly escaped
                           query = select(User).where(User.username == user_input)
                           
                           # For Django, use the ORM:
                           from django.db.models import Q
                           users = User.objects.filter(Q(username=user_input))
                           ```
                           
                        4. **Secure file uploads**
                           ```python
                           import os
                           from werkzeug.utils import secure_filename
                           
                           ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
                           
                           def allowed_file(filename):
                               return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
                               
                           def process_upload(file):
                               if file and allowed_file(file.filename):
                                   filename = secure_filename(file.filename)
                                   file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                           ```
                           
                        5. **Use CSRF protection**
                           ```python
                           # Flask with Flask-WTF
                           from flask_wtf.csrf import CSRFProtect
                           
                           app = Flask(__name__)
                           csrf = CSRFProtect(app)
                           
                           # Django has built-in CSRF protection
                           # In forms:
                           {% csrf_token %}
                           ```
                           
                        6. **Rate limiting**
                           ```python
                           # Using Flask-Limiter
                           from flask_limiter import Limiter
                           from flask_limiter.util import get_remote_address
                           
                           limiter = Limiter(
                               app,
                               key_func=get_remote_address,
                               default_limits=["200 per day", "50 per hour"]
                           )
                           
                           @app.route("/login", methods=["POST"])
                           @limiter.limit("10 per minute")
                           def login():
                               # login logic
                           ```
                           
                        7. **Proper error handling**
                           ```python
                           # Flask example
                           @app.errorhandler(404)
                           def page_not_found(e):
                               return render_template('404.html'), 404
                               
                           @app.errorhandler(500)
                           def internal_server_error(e):
                               # Log the error
                               app.logger.error(f"Server error: {e}")
                               return render_template('500.html'), 500
                           ```
                        """)
            
            except Exception as e:
                st.error(f"❌ Error scanning website: {str(e)}")
                st.markdown("""
                    This could be due to:
                    - The website blocking automated requests
                    - Connection timeout
                    - Invalid domain name
                    - Firewall restrictions
                    
                    Try scanning a different website or check your connection.
                """)

# Add a section at the bottom for educational content when no scan is in progress
if not scan_button or not url or not is_valid_url(url):
    st.markdown("---")
    
    st.subheader("📚 Learn About Web Security")
    
    learn_tab1, learn_tab2, learn_tab3 = st.tabs([
        "Security Headers", 
        "SSL/TLS Basics", 
        "Common Vulnerabilities"
    ])
    
    with learn_tab1:
        st.markdown("""
        ### Essential Security Headers
        
        Security headers are HTTP response headers that your web server can set to enhance the security of your website. They help protect against various common attacks.
        
        | Header | Purpose |
        | ------ | ------- |
        | **Content-Security-Policy** | Prevents XSS attacks by specifying which dynamic resources are allowed to load |
        | **X-Frame-Options** | Prevents clickjacking attacks by ensuring your site cannot be embedded in frames on other sites |
        | **X-Content-Type-Options** | Prevents MIME-type sniffing attacks by ensuring browsers respect the declared content type |
        | **Strict-Transport-Security** | Enforces HTTPS connections and prevents SSL-stripping attacks |
        | **Referrer-Policy** | Controls how much referrer information is included with requests |
        | **Permissions-Policy** | Controls which browser features and APIs can be used by the website |
        """)
        
    with learn_tab2:
        st.markdown("""
        ### SSL/TLS Security Basics
        
        Transport Layer Security (TLS) - formerly known as SSL - provides encrypted connections between a client and server.
        
        **Key aspects of good SSL/TLS configuration:**
        
        1. **Use modern protocols** - TLSv1.2 or TLSv1.3 should be used. Older protocols like TLSv1.0, TLSv1.1, and all SSL versions are considered insecure.
        
        2. **Strong cipher suites** - Only use cipher suites with strong encryption algorithms and forward secrecy.
        
        3. **Valid certificates** - Certificates should be issued by trusted CAs, not be expired, and match the domain name.
        
        4. **HSTS implementation** - Strict-Transport-Security header tells browsers to only use HTTPS.
        
        5. **Certificate transparency** - Modern certificates should appear in public CT logs for verification.
        """)
        
    with learn_tab3:
        st.markdown("""
        ### Common Web Vulnerabilities
        
        1. **Cross-Site Scripting (XSS)** - Attackers inject malicious scripts that execute in users' browsers
           - Prevent with: Content-Security-Policy, input sanitization, output encoding
        
        2. **SQL Injection** - Attackers manipulate SQL queries through unsanitized inputs
           - Prevent with: Prepared statements, ORM frameworks, input validation
           
        3. **Cross-Site Request Forgery (CSRF)** - Forces users to perform unwanted actions on sites they're logged into
           - Prevent with: Anti-CSRF tokens, SameSite cookies, checking Origin/Referer headers
        
        4. **Insecure Deserialization** - Untrusted data is deserialized by an application
           - Prevent with: Input validation, integrity checks, type checking
        
        5. **Security Misconfiguration** - Improper security settings expose vulnerabilities
           - Prevent with: Secure configuration standards, automated scanning, minimal exposure
           
        6. **Broken Authentication** - Flaws in authentication mechanisms
           - Prevent with: Multi-factor authentication, strong password policies, proper session management
        """)

    # Tips for implementing security in Python - now as a separate section, not inside an expander
    st.subheader("Python Web Security Implementation")
    
    python_sec_tab1, python_sec_tab2 = st.tabs(["Flask Example", "Django Example"])
    
    with python_sec_tab1:
        st.code("""
from flask import Flask, request, session
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate strong secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # SameSite cookie attribute
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Session timeout

@app.after_request
def add_security_headers(response):
    # Add security headers
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
        """, language="python")
    
    with python_sec_tab2:
        st.code("""
# In settings.py

# Generate a strong secret key in production
SECRET_KEY = 'your-secure-secret-key'

# Security settings
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = 'DENY'

# Set CSP headers with django-csp
INSTALLED_APPS = [
    # ...
    'csp',
    # ...
]

MIDDLEWARE = [
    # ...
    'csp.middleware.CSPMiddleware',
    # ...
]

CSP_DEFAULT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_SCRIPT_SRC = ("'self'",)
CSP_IMG_SRC = ("'self'", "data:")
        """, language="python")