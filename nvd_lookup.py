import os
import requests
from dotenv import load_dotenv

# ==========================================
# 1. LOAD API CONFIGURATION
# ==========================================

# Load out environment variables from .env
load_dotenv()

# retrieve our private NVD API key
api_key = os.getenv("NVD_API_KEY")

# Store the official NVD API endpoint
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Check whether Python successfully loaded the API key
# Only print True or Flase, never the key itself
print("API key loaded:", bool(api_key))


# ==========================================
# 2. CREATE A REUSABLE LOOKUP FUNCTION
# ==========================================

def get_cve_data(cve_id):
    # Stop if the API key is missing
    if not api_key:
        raise ValueError("NVD_API_KEY was not found in .env")

    # Prepare the API authentication header
    headers = {"apiKey": api_key}

    # Tell NVD which CVE we want to look up
    params = {"cveId": cve_id}

    # Send the HTTP request to NVD
    response = requests.get(
        NVD_URL,
        headers=headers,
        params=params,
        timeout=30
    )

    # Raise an error if NVD returns an unsuccessful status
    response.raise_for_status()

    # Convert the JSON response into Python data
    data = response.json()

    # Return the response so other code can use it
    return data

# ==========================================
# 3. Extract CVSS 3.1 information
# ==========================================

def get_cvss_score(data):
    # Check whether NVD returned any vulnerability records
    if not data["vulnerabilities"]:
        return None

    # Get the first vulnerability from the API response
    vulnerability = data["vulnerability"][0]["cve"]

    # Get the dictionary containing CVSS metrics
    metrics = vulnerability.get("metrics", {})

    # Get CVSS version 3.1 metrics if they exist
    cvss_list = metrics.get("cvssMetricsV31", [])

    # Some vulnerabilities have no CVSS 3.1 score
    # Return None rather than causing an error
    if not cvss_list:
        return None

    # Extract the first CVSS 3.1 metricclear

    cvss_data = cvss_list[0]["cvssData"]

    # Get the numerical score and severity rating
    score = cvss_data["baseScore"]
    severity = cvss_data["baseSeverity"]

    # Return both values to the calling code
    return score, severity

# Request the Log4Shell vulnerability
result = get_cve_data("CVE-2021-44228")

# Display the number of matching records
print("Vulnerabilities found:", result["totalResults"])

