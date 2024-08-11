
# CESNET Domain Name Processing Project

This document describes the project work on handling CESNET files containing over 500 million internet domain names collected over six months. The data handling process is divided into three main steps: filtering domains based on a threshold, identifying common domains across the months, and reducing suffixes.

## Step 1: Filter Domains Based on Threshold

The first step is to filter domains that have been accessed more than a specified threshold. This step creates a `most_frequent` directory and saves the filtered domain data into it. We decided to keep domains that appeared at least 10 times in the data, reducing the number of domains to process and keeping only the most relevant ones.

### Process:
- Read CESNET `.csv.gz` files.
- Filter out domains with appearance counts below the threshold.
- Save the filtered data into the `most_frequent` directory.

## Step 2: Identify Common Domains Across Months

The second step identifies common domains across the filtered files from different months. This step processes the filtered files and saves the common domains into a file.

### Process:
- Create a `filtered` directory inside `most_frequent`.
- Process the filtered files to extract and sort domain names.
- Identify common lines among the filtered files.
- Save the common domains into `cesnet_intersect_threshold.txt`.

## Step 3: Suffix Reduction

The third step involves reducing suffixes to manage the domain data more effectively.

### Process:
- Extract the registered domain and top-level domain (TLD) from each domain.
- Filter out rows with missing suffixes.
- Drop a percentage of rows for the most common suffixes to reduce their dominance.
- Group by suffix and sample to limit the number of domains per suffix.
- Save the final sampled data to a file.

### Detailed Steps:
- Extract the registered domain and TLD.
- Filter out rows with empty suffixes.
- Drop a specified ratio of rows for the top suffixes.
- Group by suffix and sample a limited number of domains per suffix.
- Save the undersampled domains to a file.
- Take a final sample and save it to a file with a specified sample size.

## Example Usage

To execute the entire domain processing pipeline, follow these steps:

1. **Filter Domains Based on Threshold**
   ```bash
   python3 threshold_filter.py
   ```

2. **Identify Common Domains Across Months**
   ```bash
   bash cesnet_common_domains.sh
   ```

3. **Suffix Reduction**
   Run the suffix reduction script in your preferred environment (e.g., Jupyter Notebook).

This structured approach ensures efficient handling and analysis of the extensive CESNET domain data.
