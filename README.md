# KEV to CVSS Vulnerability Pipeline

## Project Overview

This project is a Python-based cybersecurity data analysis pipeline that combines vulnerability information from two sources:

- **CISA Known Exploited Vulnerabilities (KEV) Catalog:** Identifies vulnerabilities known to have been exploited in the wild.
- **National Vulnerability Database (NVD):** Provides additional vulnerability information, including CVSS severity scores.

### Project Goal

Identify and rank known exploited vulnerabilities based on their CVSS severity scores to better understand which vulnerabilities are both exploited and highly severe.

**Important:** CVSS measures vulnerability severity, not the likelihood of exploitation or an organization's overall risk. A vulnerability's presence in KEV confirms known exploitation, but neither metric alone provides a complete risk assessment.

## Technologies

- Python
- requests
- pandas
- NVD API (planned)
- Matplotlib (planned)
- Git and GitHub

## Current Progress

- [x] Set up Python development environment
- [x] Connect to CISA's KEV catalog
- [x] Retrieve vulnerability data in JSON format
- [x] Convert vulnerability records into a pandas DataFrame
- [x] Extract relevant vulnerability information
- [x] Filter vulnerabilities by date
- [ ] Analyze vulnerability trends
- [ ] Connect to the NVD API
- [ ] Retrieve CVSS severity scores
- [ ] Rank vulnerabilities
- [ ] Create data visualizations
- [ ] Write a findings report

## Project Scope

The initial analysis will focus on vulnerabilities added to CISA's KEV catalog within the last 90 days.

## Current Setup

The project currently uses Python 3.14 and the `requests` and `pandas` packages.

To run the current script, create and activate a Python virtual environment, install the required packages, and run:

```bash
python main.py
```

Additional setup instructions will be added as the project develops.

## Project Status

**In Development — Week 1**

This project is being developed as part of a cybersecurity mentorship program to gain hands-on experience with Python, APIs, vulnerability management, and data analysis.