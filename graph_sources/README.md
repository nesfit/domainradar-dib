# Source files for generating graphs

- `domainstats.xlsx` - MS Excel file for creating barplots with data statistics for domain names (Fig. 1 and 2)
- `get_malware_domain_sources.py` - Creates a piechart with sources of malware domains (Fig. 3)
- `get_mlware_types.py` - Creates a barplot of malware types (Fig. 4)

# How to run the Python scripts:

## 1 - Set up Python Poetry environment (for package dependency compatibility)
`poetry install` \
`poetry shell`

## 2 - Edit MongoDB credentials:
Specify `MONGO_URI`, `MONGO_DB`, and `MONGO_COLLECTION` accordingly.

## 3 - Run the scripts
`python3 get_malware_domain_sources.py` \
`python3 get_malware_types.py`