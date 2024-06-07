cisco_umrella_benign_load.py

- Script fetches once month data from cisco umbrella given by specific dates specified in `date` variable.
- Unwanted domains such as ip addresses or others are filtered out from the data.
- Intersection among all monthly domains is made to preserve only recurring domains increasing their benigness.
