
# VirusTotal Domain Verification Process

This document describes the process of verifying domain names using the VirusTotal API. The goal is to determine if domains are malign or benign based on security vendor reports. This verification ensures that our datasets are correctly labeled and can be considered ground truth.

## Overview

The verification process involves checking each domain against the VirusTotal database and applying a threshold to determine its status. A domain is flagged as malign if at least 3 security vendors have reported it as malign or suspicious. A domain is flagged as benign if there are no records for it in VirusTotal.

## Steps

### 1. Setup and Configuration

- Setup logging and exception handling.
- Define configuration with API key, input mode, mode (malign/benign), and batch size.

### 2. Domain Checking with VirusTotal API

- Define a `DomainAnalyzer` class to handle domain checking using the VirusTotal API.
- Extract domain data and determine the verdict based on the number of malicious and suspicious flags.

### 3. Verdict Determination

- For malign mode, a domain is considered malign if the sum of malicious and suspicious flags exceeds 3.
- For benign mode, a domain is considered benign if there are no records of malicious or suspicious flags.

### 4. Data Handling

- Load previous data and save new data periodically as checkpoints.
- Generate a report summarizing the analysis results.

### Detailed Explanation

#### API Key Configuration

Ensure that the VirusTotal API key is set in the environment variables. This key is required to authenticate API requests.

#### DomainAnalyzer Class

The `DomainAnalyzer` class manages the process of querying VirusTotal and interpreting the results. Key methods include:

- `check_domain(domain: str)`: Queries VirusTotal for information on the given domain.
- `extract_domain_data(domain: str, result: dict)`: Extracts relevant data from the API response.
- `save_checkpoint(data, processed_domains, mode, total_processed)`: Saves progress periodically to avoid data loss.
- `generate_report(df: pd.DataFrame, output_filename: str)`: Generates a PDF report summarizing the verification results.


## Conclusion

This document outlines the systematic approach to verifying domain names using the VirusTotal API. By applying strict thresholds and thorough data handling practices, we can ensure the integrity and accuracy of our domain datasets.
