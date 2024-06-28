import os
import pandas as pd
import glob

# Create the "most_frequent" folder if it doesn't exist
output_folder = "most_frequent"
os.makedirs(output_folder, exist_ok=True)

file_paths = glob.glob("data/*.csv.gz")
threshold = 10
print(f"Threshold set to: {threshold}")

for file_path in file_paths:
    try:
        df = pd.read_csv(file_path, compression='gzip', header=None, dtype={1: str})

        df.columns = ['Domain', 'Appearance']

        # Convert the 'Appearance' column to numeric type, ignoring non-numeric values
        df['Appearance'] = pd.to_numeric(df['Appearance'], errors='coerce')

        # Calculate the median appearance count
        median = df['Appearance'].median(skipna=True)

        # Filter out domains with appearance count below the threshold
        filtered_df = df[df['Appearance'] >= threshold]
        filtered_file_path = os.path.join(output_folder, f"filtered_{os.path.basename(file_path)}")
        filtered_df.to_csv(filtered_file_path, index=False)

        print(f"Processed file: {file_path}")
        # print(f"Median: {median}")
        print(f"Filtered data saved to: {filtered_file_path}")
        print()

    except Exception as e:
        print(f"Error processing file: {file_path}")
        print(str(e))
        print()
