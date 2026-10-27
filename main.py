import requests 
import pandas as pd

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

response = requests.get(url, timeout =30)

print(response.status_code)

data = response.json()

print(type(data))
print(data.keys())

vulnerabilities = data["vulnerabilities"]

print(type(vulnerabilities))
print(len(vulnerabilities))

print(vulnerabilities[0])

first_vulnerability = vulnerabilities[0]

print(first_vulnerability["cveID"])
print(first_vulnerability["vendorProject"])
print(first_vulnerability["dateAdded"])

for vulnerability in vulnerabilities[:5]:
    print(vulnerability["cveID"])
    print("Vendor:", vulnerability["vendorProject"])
    print("Date Added:", vulnerability["dateAdded"])
    print("--------------------")

    df = pd.DataFrame(vulnerabilities)

    print(df.head())

    selected_columns = df[[
        "cveID",
        "vendorProject",
        "dateAdded",
        "knownRansomwareCampaignUse"
    ]]

    print(selected_columns.head())

    df["dateAdded"] = pd.to_datetime(df["dateAdded"])

    print(df["dateAdded"].head())

    today = pd.Timestamp.today().normalize()

    cutoff_date = today - pd.Timedelta(days=90)

    print("Today's date:", today)
    print("Cutoff date:", cutoff_date)

    recent_vulnerabilities = df[
        (df["dateAdded"] >= cutoff_date) &
        (df["dateAdded"] <= today)
    ]

    print("Total vulnerabilities:", len(df))
    print("Vulnerabilities in the last 90 days:", len(recent_vulnerabilities))