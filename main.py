import requests
import pandas as pd
import json
import time
# Import our reusable functions for retrieving NVD vulnerability data
from nvd_lookup import get_cve_data, get_cvss_score

# ==========================================
# 1. PROJECT SETTINGS
# ==========================================

# Number of days of KEV data we want to analyze
DAYS_TO_ANALYZE = 7

# Official CISA KEV catalog URL
url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ==========================================
# 2. DOWNLOAD CISA VULNERABILITY DATA
# ==========================================

# Send a request to CISA to get the KEV catalog
response = requests.get(url, timeout=30)

# Stop the program if the request failed
response.raise_for_status()

# Convert the JSON response into a Python dictionary
data = response.json()

# Save the complete CISA catalog as a local JSON file
# This preserves the original data before we filter or modify it
with open("data/raw/cisa_kev.json", "w", encoding="utf-8") as file:
    json.dump(data, file, indent=4)

# Get the list of vulnerabilities from the dictionary
vulnerabilities = data["vulnerabilities"]

# ==========================================
# 3. ORGANIZE THE DATA WITH PANDAS
# ==========================================

# Convert the list of vulnerability dictionaries into a table
df = pd.DataFrame(vulnerabilities)

# Convert the dateAdded column from text into real dates
df["dateAdded"] = pd.to_datetime(df["dateAdded"])

# ==========================================
# 4. FILTER THE LAST 7 DAYS
# ==========================================

# Get today's date
today = pd.Timestamp.today().normalize()

# Calculate the cutoff date
cutoff_date = today - pd.Timedelta(days=DAYS_TO_ANALYZE)

# Keep only vulnerabilities added within the last 7 days
recent_vulnerabilities = df[
    (df["dateAdded"] >= cutoff_date) &
    (df["dateAdded"] <= today)
]

# ==========================================
# 5. DISPLAY RESULTS
# ==========================================

# Select the columns we want to display
selected_columns = [
    "cveID",
    "vendorProject",
    "dateAdded",
    "knownRansomwareCampaignUse"
]

# Display a summary of the vulnerability data
print("\n===== CISA KEV ANALYSIS =====")
print(f"Analysis period: Last {DAYS_TO_ANALYZE} days")
print(f"Start date: {cutoff_date.date()}")
print(f"End date: {today.date()}")
print(f"Total KEV records: {len(df)}")
print(f"Records in date range: {len(recent_vulnerabilities)}")

# Create a copy of our filtered data for display
display_df = recent_vulnerabilities[selected_columns].copy()

# Number each vulnerability starting from 1
display_df.index = range(1, len(display_df) + 1)

# Give the columns shorter, easier-to-read names
display_df.columns = [
    "CVE ID",
    "Vendor",
    "Date Added",
    "Ransomware Use"
]

# Display the table with numbered rows and aligned columns
print("\n===== RECENT VULNERABILITIES =====")
# Print a formatted table with fixed column widths
print(f"\n{'#':<4} {'CVE ID':<20} {'Vendor':<20} {'Date Added':<15} {'Ransomware Use':<15}")

# Print a separator line underneath the headings
print("-" * 80)

# Print each vulnerability on its own row
for number, (_, row) in enumerate(display_df.iterrows(), start=1):
    print(
        f"{number:<4} "
        f"{row['CVE ID']:<20} "
        f"{row['Vendor']:<20} "
        f"{row['Date Added'].strftime('%Y-%m-%d'):<15} "
        f"{row['Ransomware Use']:<15}"
    )
# ==========================================
# 6. ANALYZE VULNERABILITIES BY VENDOR
# ==========================================

# Count how many times each vendor appears
# in our filtered 7-day vulnerability data
vendor_counts = recent_vulnerabilities["vendorProject"].value_counts()

#Display the five vendors with the most KEV entries
print("\n===== Top 5 VENDORS =====")
print(vendor_counts.head(5))

# ==========================================
# 7. ANALYZE RANSOMWARE CAMPAIGN USE
# ==========================================

# Select the ransomware campaign use column
# Count how many vulnerabilities are marked Known or Unknown
ransomware_counts = recent_vulnerabilities[
    "knownRansomwareCampaignUse"
].value_counts()

# Display the results
print("\n===== RANSOMWARE CAMPAIGN USE =====")
print(ransomware_counts)

# ==========================================
# 8. SAVE FILTERED VULNERABILITY DATA
# ==========================================

# Save our 7-day vulnerability data into a CSV file
# CSV files can be opened in Excel or read usuing pandas
recent_vulnerabilities.to_csv(
    "data/processed/recent_vulnerabilities.csv",
    index=False
)

# Confirm that the file was saved
print("\nVulnerability data saved successfully!")

# ==========================================
# 9. LOOK UP CVSS SCORES FOR MULTIPLE CVEs
# ==========================================

# Create a list to store the results of our NVD lookups
cvss_results = []

# Select the first 3 vulnerabilities for testing
test_vulnerabilities = recent_vulnerabilities.head(3)

# Loop through each vulnerability in our test dataset
for _, row in test_vulnerabilities.iterrows():

    # Get the CVE identifier from the current row
    cve_id = row["cveID"]

    print("\nLooking up:", cve_id)

    # Request vulnerability information from NVD
    nvd_data = get_cve_data(cve_id)

    # Extract its CVSS 3.1 score and severity
    cvss_result = get_cvss_score(nvd_data)

    # Check whether CVSS information was available
    if cvss_result is not None:
        score, severity = cvss_result
    else:
        # Store missing scores as None instead of guess
        score, severity = None, None

    # Save the information in a dictionary
    cvss_results.append({
        "cveID": cve_id,
        "cvssScore": score,
        "severity": severity
    })

    # Display the result
    print("Score:", score)
    print("Severity:", severity)

    # Pause between API requests to respect rate limits
    time.sleep(6)


# ==========================================
# 10. DISPLAY FINAL NVD RESULTS
# ==========================================

# Convert our collected results into a pandas DataFrame
# This happens after all three vulnerabilities have been processed
cvss_df = pd.DataFrame(cvss_results)

# Display our results in one table
print("\n===== NVD CVSS RESULTS =====")
print(cvss_df.to_string(index=False))


# ==========================================
# 11. SAVE NVD CVSS RESULTS
# ==========================================

# Save the CVSS scores we retrieved from NVD
# This creates a CVS file that pandas can read later
cvss_df.to_csv(
    "data/processed/nvd_cvss_scores.csv",
    index=False
)

# Confirm that the file was saved successfully
print("\nNVD CVSS scores saved successfully!")


# ==========================================
# 12. COMBINE CISA AND NVD DATA
# ==========================================

# Join our CISA vulnerability records wirh NVD scores
# The cveID column is present in both datasets
# A left join keeps all CISA records, even without NVD scores
combined_df = recent_vulnerabilities.merge(
    cvss_df,
    on="cveID",
    how="left"
)

# Select the columns we want to display
combined_columns = [
    "cveID",
    "vendorProject",
    "dateAdded",
    "cvssScore",
    "severity"
]

# Display the combined table
print("\n===== COMBINED CISA + NVD DATA =====")
print(combined_df[combined_columns].to_string(index=False))





