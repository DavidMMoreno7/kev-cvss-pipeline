import os
import requests
from dotenv import load_dotenv

#===========================================
# 1. LOAD ENVIRONMENT VARIABLES
#===========================================

# Load variables from our .env file
load_dotenv()

# Retrieve the API key without putting it in our code
api_key = os.getenv("NVD_API_KEY")

# STop if the API key is missing
if not api_key:
    raise ValueError("NVD_API_KEY is missing from the .env file")

# ==========================================
# 2. PREPARE THE NVD API REQUEST
# ==========================================

# Official NVD API endpoint
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Choose one vulnerability to look up
cve_id = "CVE-2021-44228"

# Send our API key in the request header
headers = {"apiKey": api_key}

# Specify which CVE we want
params = {"cveId": cve_id}

# Check that our API parameters are stored as a dictionary
print("Parameters:", params)
print("Parameter type:", type(params))

# ==========================================
# 3. SEND THE REQUEST
# ==========================================

response = requests.get(
    url,
    headers=headers,
    params=params,
    timeout=30
)

# CHeck whether the request was successful
print("HTTP Status COde:", response.status_code)

# Stop if NVD returned an HTTP error
response.raise_for_status()

# Convert the JSON response into a Python dictionary
data = response.json()

# Display how many vulnerability records were returned
print("Vulnerabilities found:", data["totalResults"])

# ==========================================
# 4. EXTRACT VULNERABILITY INFORMATION
# ==========================================

# Get the first vulnerability from NVD's response
vulnerability = data["vulnerabilities"][0]["cve"]

# Get the CVSS scoring information
metrics = vulnerability["metrics"]

# Display the available CVSS metric versions
print("Available CVSS metrics:", metrics.keys())

# ==========================================
# 5. EXTRACT CVSS 3.1 SCORE AND SEVERITY
# ==========================================

# Get the CVSS 3.1 metrics from the NVD record
cvss_metrics = metrics["cvssMetricV31"][0]

# Get the numerical CVSS base score
cvss_score = cvss_metrics["cvssData"]["baseScore"]

# Get the severity classification
cvss_severity = cvss_classification = cvss_metrics["cvssData"]["baseSeverity"]

# Display the results
print("\n===== CVSS INFORMATION =====")
print("CVE ID:", cve_id)
print("CVSS Score:", cvss_score)
print("Severity:", cvss_severity)
