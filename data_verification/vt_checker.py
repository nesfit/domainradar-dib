#!/usr/bin/env python
# coding: utf-8

# Import standard libraries
import os
import datetime
import subprocess
import logging
from dataclasses import dataclass
from typing import Optional, Tuple
import math
import functools
import time

# Import third-party libraries
import pandas as pd
import pyarrow.parquet as pq
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from dotenv import load_dotenv
from tqdm import tqdm
import requests

# Set up the environment for running async code in Jupyter notebooks
import nest_asyncio
nest_asyncio.apply()

mode = 'malign'  # You can change this to 'benign' to read from the malign dataset
input_mode = 'txt'  # You can change this to 'parquet'
batch_size = 500 # Maximum of api calls for VirusTotal, current academic api is 20k per day, the provided api key is only for 500 calls per day


def setup_logging():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(os.environ.get("LOGLEVEL", "INFO"))
    root.addHandler(handler)
    logging.info("Logging is set up.")
setup_logging()


def exception_handler(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {method.__name__}: {e}", exc_info=True)
            return None
    return wrapper

@dataclass
class Config:
    load_dotenv()
    api_key: str = os.getenv('VT_API_KEY', '')
    input_mode: str = 'parquet'
    mode: str = 'malign'
    batch_size: int = 3

    def __post_init__(self):
        if not self.api_key:
            logging.error("API key is not set. Please set the VT_API_KEY environment variable.")
            raise ValueError("API key is not set")
config = Config()


class DomainAnalyzer:
    """
    A class for analyzing domains using the VirusTotal API.

    Attributes:
        api_key (str): The API key for accessing the VirusTotal API.
        headers (dict): The headers to be used in API requests.

    Methods:
        _create_headers(): Create the headers for API requests.
        check_domain(domain: str) -> Optional[dict]: Check a domain for information using the VirusTotal API.
        _determine_verdict(analysis_stats: dict) -> str: Determine the verdict (benign or malign) based on analysis statistics.
        _is_domain_live(domain: str) -> str: Check if a domain is alive.
        _format_timestamp(timestamp) -> str: Format a timestamp into a string.
        extract_domain_data(domain: str, result: dict) -> Optional[Tuple]: Extract domain data from the result.
        load_previous_data(mode: str) -> pd.DataFrame: Load previous data from a file.
        save_data(df: pd.DataFrame, mode) -> None: Save data to a file.
        save_checkpoint(data, processed_domains, mode, total_processed): Save a checkpoint of data and processed domains.
        generate_report(df: pd.DataFrame, output_filename: str, rows_per_page: int = 500) -> None: Generate a report based on the DataFrame and save it as a PDF.
        process_selected_domains(input_mode: str, mode: str, batch_size) -> pd.DataFrame: Process selected domains based on the input mode and mode.
    """

    def __init__(self):
        self.api_key = config.api_key
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    # Rest of the code...
class DomainAnalyzer:
    def __init__(self):
        self.api_key = config.api_key
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        self.total_flags = 0


    @exception_handler
    def _create_headers(self):
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        pass

    @exception_handler
    def check_domain(self, domain: str) -> Optional[dict]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            logging.warning(f"Quota exceeded when attempting to fetch information for domain {domain}.")
            return "Quota Exceeded"
        else:
            logging.error(f"Error: Unable to fetch information for domain {domain}. {response.text}")
            return None

    @exception_handler
    def _determine_verdict(self, analysis_stats: dict, mode: str) -> str:
        total_malign_suspicious = analysis_stats.get('malicious', 0) + analysis_stats.get('suspicious', 0)
        # mode is 'benign'
        if mode == 'benign':
            return "Benign" if total_malign_suspicious == 0 else "Malign"
        else:  # mode is 'malign'
            return "Malign" if total_malign_suspicious > 3 else "Benign"
    
    @exception_handler
    def _is_domain_live(self, domain: str) -> str:
        try:
            result = subprocess.run(['./livetest.sh', domain], capture_output=True, text=True)
            return "Alive" if result.stdout.strip() == '1' else "Dead"
        except Exception as e:
            logging.error(f"Error: Unable to check if domain {domain} is live. {e}")
            return "Unknown"
        
    @exception_handler
    def _format_timestamp(self, timestamp):
        return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    @exception_handler
    def extract_domain_data(self, domain: str, result: dict) -> Optional[Tuple]:
        try:
            attributes = result['data']['attributes']
            analysis_stats = attributes['last_analysis_stats']
            verdict = self._determine_verdict(analysis_stats, mode)
            detection_ratio = f"{analysis_stats['malicious']}/{analysis_stats['malicious'] + analysis_stats['harmless']}"
            suspicious_count = analysis_stats.get('suspicious', 0)
            malicious_count = analysis_stats.get('malicious', 0)

            total_flags = suspicious_count + malicious_count
            self.total_flags += total_flags

            last_analysis_date = attributes.get('last_analysis_date', attributes.get('last_submission_date', 0))
            formatted_timestamp = self._format_timestamp(last_analysis_date) if last_analysis_date else 'N/A'

            domain_status = self._is_domain_live(domain)
            
            return (domain, verdict, detection_ratio, formatted_timestamp, 
                    analysis_stats.get('harmless', 0), malicious_count, suspicious_count, domain_status)
        except KeyError:
            print(f"Error: Could not extract analysis stats for domain {domain}")
            return None

    @exception_handler
    def load_previous_data(self, mode: str) -> pd.DataFrame:
        previous_data_filename = f'previous_data_{mode}.csv'
        if os.path.exists(previous_data_filename):
            return pd.read_csv(previous_data_filename)
        else:
            columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
            return pd.DataFrame(columns=columns)

    @exception_handler
    def save_data(self, df: pd.DataFrame, mode) -> None:
        df.to_csv(f'previous_data_{mode}.csv', index=False)

    @exception_handler
    def save_checkpoint(self, data, processed_domains, mode, total_processed):
        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        new_df = pd.DataFrame(data, columns=columns)

        # Load the previous data
        old_df = self.load_previous_data(mode)
        
        # Merge the old and new data, removing duplicates
        merged_df = pd.concat([old_df, new_df]).drop_duplicates(subset=['Domain']).reset_index(drop=True)
        self.save_data(merged_df, mode)

        # Overwrite the processed domains file with the updated list
        processed_domains_file = f"processed_domains_{mode}.txt"
        with open(processed_domains_file, 'w') as file:
            file.write('\n'.join(processed_domains))
        logging.info(f"Checkpoint saved to previous_data_{mode}.csv and processed_domains_{mode}.txt")


    @exception_handler
    def generate_report(self, df: pd.DataFrame, output_filename: str, rows_per_page: int = 500) -> None:
        """
        Generate a report based on the DataFrame and save it as a PDF, including a summary at the end.
        """
        num_pages = math.ceil(len(df) / rows_per_page)

        benign_count = len(df[df['Verdict'] == 'Benign'])
        malign_count = len(df[df['Verdict'] == 'Malign'])
        total_count = len(df)

        with PdfPages(output_filename) as pdf_pages:
            for page in range(num_pages):
                start_row = page * rows_per_page
                end_row = start_row + rows_per_page
                page_df = df[start_row:end_row]

                # If it's the last page, add the summary rows
                if page == num_pages - 1:
                    page_df = page_df.fillna('-')
                    summary_df = pd.DataFrame({
                        "Domain": ["", ""],
                        "Verdict": ["Benign count", "Malign count"],
                        "Detection Ratio": [f"{benign_count}/{total_count}", f"{malign_count}/{total_count}"],
                        # Other columns can be filled with appropriate data or left empty
                    }).reindex(columns=page_df.columns).fillna('-')

                    page_df = pd.concat([page_df, summary_df], ignore_index=True)

                fig_height = max(len(page_df) * 0.01, 4.8)  # Ensure a minimum height
                fig, ax = plt.subplots(figsize=(11, fig_height))
                
                ax.axis('off')  # Hide axes
                plt.tight_layout(pad=0.2)

                colWidths = [
                    max(page_df["Domain"].apply(lambda x: len(x) if x is not None else 0).max() * 0.25, 0.1) * 0.02 if column == "Domain" 
                    else 0.15 if column == "Detection Timestamp" 
                    else 0.1 for column in page_df.columns
                ]

                tab = pd.plotting.table(ax, page_df, loc='upper center', colWidths=colWidths, cellLoc='center', rowLoc='center')
                tab.auto_set_font_size(False)
                tab.set_fontsize(8)
                tab.scale(1.2, 1.2)

                for key, cell in tab.get_celld().items():
                    if key[0] == 0 or key[1] == -1:
                        cell.get_text().set_weight('bold')
                    if 'Verdict' in page_df.columns:
                        if cell.get_text().get_text() == 'Malign':
                            cell.set_text_props(color='red')
                        elif cell.get_text().get_text() == 'Benign':
                            cell.set_text_props(color='green')
                    if 'Live Status' in page_df.columns:
                        if cell.get_text().get_text() == 'Alive':
                            cell.set_text_props(color='green')
                        elif cell.get_text().get_text() == 'Dead':
                            cell.set_text_props(color='red')
                    if key[1] == -1:
                        cell.set_visible(False)
                    if page == num_pages - 1 and key[0] >= len(page_df) - 1:  # This line is changed
                        cell.set_text_props(weight='bold')
                        cell.get_text().set_color('black')
                        cell.set_facecolor('lightgrey')

                pdf_pages.savefig(fig, bbox_inches='tight')
                plt.close(fig)

    @exception_handler
    def process_selected_domains(self, input_mode: str, mode: str, batch_size) -> pd.DataFrame:
        # Check if the input mode is valid
        if input_mode not in ['parquet', 'txt']:
            print(f"Invalid input mode '{input_mode}'. Please use 'parquet' or 'txt'.")
            return pd.DataFrame()

        # Define the paths for the input files based on the input mode and mode
        paths = {
            #define files for benign and malign modes
            'parquet': {
                'malign': 'example_data/example.parquet',
                'benign': 'example_data/example.parquet'
            },
            'txt': {
                'malign': 'example_data/example.txt',
                'benign': 'example_data/example.txt',
            }
        }

        # Read the domain names from the input file
        if input_mode == 'parquet':
            table = pq.read_table(paths[input_mode][mode])
            domain_names = table.column('domain_name').to_pandas()
        else:  # input_mode == 'txt'
            with open(paths[input_mode][mode], 'r') as file:
                domain_names = file.read().splitlines()

        # Load the list of processed domains
        processed_domains_file = f"processed_domains_{mode}.txt"
        if os.path.exists(processed_domains_file):
            with open(processed_domains_file, 'r') as file:
                processed_domains = file.read().splitlines()
        else:
            processed_domains = []

        data = []
        processed_in_this_run = 0
        total_processed = len(processed_domains)
        
        # Create a progress bar to track the processing progress
        progress_bar = tqdm(total=len(domain_names), desc='Processing domains', unit='domain')
        for domain in domain_names:
            progress_bar.update(1)
            if domain not in processed_domains:
                try:
                    # Check the domain and get the result
                    result = self.check_domain(domain)
                    if result == "Quota Exceeded":
                        # Quota exceeded, generate report and exit
                        print("Quota is exceeded, generating report...")
                        df = self.load_previous_data(mode)
                        df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
                        df.dropna(inplace=True)
                        progress_bar.close()
                        return df
                    elif result:
                        # Extract data if domain check was successful
                        data.append(self.extract_domain_data(domain, result))
                        processed_domains.append(domain)  # Assuming processed_domains is a set
                        processed_in_this_run += 1
                        total_processed += 1
                        
                        # Checkpoint save logic remains unchanged
                        if total_processed % 1000 == 0:
                            self.save_checkpoint(data, processed_domains, mode, total_processed)
                except Exception as e:
                    print(f"Unexpected error occurred: {e}")
                if processed_in_this_run >= batch_size:
                    break
        progress_bar.close()

        # Save the checkpoint and update the processed domains file
        self.save_checkpoint(data, processed_domains, mode, total_processed)
        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        
        # Create a DataFrame from the newly processed data
        new_df = pd.DataFrame(data, columns=columns)
        old_df = self.load_previous_data(mode)

        if old_df.empty:
            merged_df = new_df
        elif new_df.empty:
            merged_df = old_df
        else:
            merged_df = pd.concat([old_df, new_df]).drop_duplicates(subset=['Domain']).reset_index(drop=True)
        
        # Sort the merged data by Verdict and Live Status
        merged_df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
        merged_df.dropna(inplace=True)
        # Save the merged data
        self.save_data(merged_df, mode)
        # Print the number of domains processed
        print(f"Total number of domains processed: {len(merged_df)} out of {len(domain_names)} ({len(merged_df)/len(domain_names)*100:.2f}%)")
        return merged_df

# Run the internet domain names analysis
with DomainAnalyzer() as analyzer:  
    df = analyzer.process_selected_domains(input_mode, mode, batch_size) 
    if df is not None and not df.empty:  
        # Generate a report in pdf
        analyzer.generate_report(df, f'{mode}_VT_check.pdf') 
        print(f'Report saved as {mode}_VT_check.pdf')
    else:
        print(f"No domains processed for mode '{mode}'. No report generated.")
