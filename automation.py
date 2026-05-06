import concurrent.futures
import pandas as pd
import socket
import requests
import whois
from urllib.parse import urlparse

# ---------------------------
# LOAD FILES
# ---------------------------

scorecard_file = "security_scorecard.csv"
domains_file = "Gannett_Domains.xlsx"
ips_file = "gannett_ips.xlsx"

scorecard_df = pd.read_csv(scorecard_file)
scorecard_df.columns = scorecard_df.columns.str.strip().str.lower()
domains_df = pd.read_excel(domains_file)
ips_df = pd.read_excel(ips_file)

# Normalize master lists
master_domains = set(domains_df.iloc[:, 0].str.lower().str.strip())
master_ips = set(ips_df.iloc[:, 0].astype(str).str.strip())

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

def clean_domain(Domain):
    return Domain.strip().lower().rstrip('.')

def resolve_ip(Domain):
    try:
        return socket.gethostbyname(Domain)
    except:
        return None

def check_redirect(Domain):
    try:
        response = requests.get(f"http://{Domain}", allow_redirects=True, timeout=5)
        final_url = response.url
        return final_url
    except:
        return None

def check_whois(Domain):
    try:
        w = whois.whois(Domain)
        return str(w).lower()
    except:
        return ""

def check_ns(Domain):
    try:
        ns = socket.getaddrinfo(Domain, None)
        return str(ns).lower()
    except:
        return ""

def ownership_keywords_found(text):
    keywords = ["gannett", "usatoday", "newsquest"]
    return any(k in text for k in keywords)

lookup_executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)

def run_with_timeout(fn, *args, timeout=10):
    future = lookup_executor.submit(fn, *args)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        future.cancel()
        return None
    except Exception:
        return None

# ---------------------------
# MAIN LOGIC
# ---------------------------

true_positive = []
false_positive = []
needs_review = []

row_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)

def process_scorecard_row(row):
    domain = clean_domain(row['domain'])
    result = {
        "Domain": domain,
        "Status": "",
        "Reason": ""
    }

    # STEP 2: MASTER LIST CHECK
    if domain in master_domains:
        result["Status"] = "TRUE POSITIVE"
        result["Reason"] = "Matched Master Domain List"
        return result

    ip = resolve_ip(domain)
    if ip and ip in master_ips:
        result["Status"] = "TRUE POSITIVE"
        result["Reason"] = "Matched Master IP List"
        return result

    # STEP 3: TECHNICAL CHECKS
    redirect_url = check_redirect(domain)
    whois_data = run_with_timeout(check_whois, domain, timeout=8)
    ns_data = run_with_timeout(check_ns, domain, timeout=8)
    combined_text = f"{redirect_url} {whois_data} {ns_data}".lower()

    if ownership_keywords_found(combined_text):
        result["Status"] = "LIKELY TRUE POSITIVE"
        result["Reason"] = "Keyword match in WHOIS/NS/Redirect"
        return result

    result["Status"] = "MANUAL REVIEW REQUIRED"
    result["Reason"] = "No ownership evidence found"
    return result

futures = [row_executor.submit(process_scorecard_row, row) for _, row in scorecard_df.iterrows()]
for future in concurrent.futures.as_completed(futures):
    result = future.result()
    if result["Status"] in ("TRUE POSITIVE", "LIKELY TRUE POSITIVE"):
        true_positive.append(result)
    else:
        needs_review.append(result)

row_executor.shutdown(wait=True)
lookup_executor.shutdown(wait=True)

# ---------------------------
# FINAL CLASSIFICATION
# ---------------------------

# Everything not in true_positive or needs_review → false_positive
all_checked_domains = set([d["Domain"] for d in true_positive + needs_review])

for _, row in scorecard_df.iterrows():
    domain = clean_domain(row['domain'])
    if domain not in all_checked_domains:
        false_positive.append({
            "Domain": domain,
            "Status": "FALSE POSITIVE",
            "Reason": "No ownership found"
        })

# ---------------------------
# EXPORT OUTPUT
# ---------------------------

pd.DataFrame(true_positive).to_csv("true_positive.csv", index=False)
pd.DataFrame(false_positive).to_csv("false_positive.csv", index=False)
pd.DataFrame(needs_review).to_csv("needs_manual_review.csv", index=False)

print("✅ Processing Complete")