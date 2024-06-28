#!/bin/bash

# Create the 'filtered' directory if it doesn't exist
mkdir -p ../most_frequent/filtered

# Loop through all files in the 'most_frequent' directory
filtered_files=()
for f in ../most_frequent/filtered_domain_datafile.trapcap.*.csv.gz; do
  if [ -f "$f" ]; then
    zcat "$f" | tail -n +4 | cut -d ',' -f 1 | sort > "../most_frequent/filtered/$(basename "${f%.gz}").filtered"
    filtered_files+=("../most_frequent/filtered/$(basename "${f%.gz}").filtered")
  fi
done

# Find common lines among the filtered files and save to 'cesnet_intersect_threshold.txt'
if [ ${#filtered_files[@]} -gt 0 ]; then
  comm -12 <(sort "${filtered_files[0]}") <(sort "${filtered_files[@]:1}") |
  sed 's/^www\.//' | sed 's/^"//' | sed 's/"$//' | awk 'NF' > ../most_frequent/filtered/cesnet_intersect_threshold.txt
else
  echo "No filtered files found."
fi
