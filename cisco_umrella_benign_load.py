from io import BytesIO
import requests
import pandas as pd
import numpy as np

dates = [f'2022-0{i}' for i in range(1, 10)] + [f'2022-{i}' for i in range(10, 13)] +[f'2023-0{i}' for i in range(1, 3)]

domains_df = None

for date in dates:
    result = requests.get(f"http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m-{date}-01.csv.zip")
    tmp_df = pd.read_csv(BytesIO(result.content), compression='zip', header=None)
    tmp_df.columns = [date, 'domain']

    if domains_df is not None:
        domains_df = pd.merge(domains_df, tmp_df, how='outer', left_on='domain', right_on='domain')
    else:
        domains_df = tmp_df

domains_df['domain'] = domains_df['domain'].str.strip().str.strip(to_strip='.')
repeating_df = domains_df.dropna()

def preprocess(df):
    # extraction
    def shift(row):
        if row[1] is None:
            row[2] = row[0]
            row[0] = None
        if row[2] is None:
            row[2] = row[1]
            row[1] = row[0]
            row[0] = None

        return row

    tmp_df = df['domain'].str.rsplit('.', n=2, expand=True).apply(shift, axis=1)
    tmp_df.columns = ['subdomains', 'sld', 'tld']

    df[['subdomains', 'sld', 'tld']] = tmp_df
    df['domain_levels'] = df['domain'].str.split('.').str.len()
    df['domain_len'] = df['domain'].str.len()
    df['tld_len'] = df['tld'].str.len()

    # filtering out bad stuff appearing in captures:
    # - characters
    # - domain levels (1)
    # - IP addresses
    # - max possible tld len is 63

    df = df[~df["domain"].str.contains("\?|:|,|\*|\(|\)|@|\{|\}")]
    df = df[~df["domain"].str.contains("\d+\.\d+\.\d+")]
    df = df[df['domain_levels'] > 1]
    df = df[df['tld_len'] < 64]

    return df

repeating_df = preprocess(repeating_df)

repeating_df['domain'].to_csv('cisco_umbrella_year_filtered_domains.csv')
