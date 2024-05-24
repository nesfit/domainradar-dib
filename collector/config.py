__author__ = ["Adam Horák", "Ondřej Ondryáš"]

from os import getenv

from dotenv import load_dotenv

load_dotenv()


class Config:
    # Base timeout for remote requests, in seconds
    TIMEOUT = 5
    # Maximum time to wait for a TLS handshake, in seconds
    TLS_TIMEOUT = 10
    # Number of retries for non-blocking TLS connections
    TLS_NONBLOCKING_RETRIES = 10
    # DNS servers to use for resolving
    DNS_SERVERS = ['193.17.47.1', '185.43.135.1']
    # DNS record types to resolve
    DNS_RECORD_TYPES = ('A', 'AAAA', 'SOA', 'CNAME', 'MX', 'NS', 'TXT')
    # DNS record types to collect IPs from
    COLLECT_IPS_FROM = ('A', 'AAAA', 'CNAME')
    # If true, the ICMP resolver will run in privileged mode
    # (requires root/administrator privileges or special system permissions)
    ICMP_PRIVILEGED = False
    # Maximum number of ThreadPoolExecutor workers (i.e. simultaneously running collection tasks)
    MAX_WORKERS = None
    # Enable process timing
    ENABLE_TIMING = False
    # MongoDB connection properties
    MONGO_URI = getenv('DR_MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB = 'drdb'
    # Entries to process in one batch
    PROCESSING_BATCH_SIZE = 100
    # Number of results to put in a buffer before writing to MongoDB
    MONGO_WRITE_BATCH_SIZE = 50
    # Maximum time to wait for a batch to be processed, in seconds
    TIMEOUT_PER_BATCH = PROCESSING_BATCH_SIZE * 4
    # Maximum time that the collection process may run without any progress before being killed, in seconds
    MAXIMUM_TIME_WITHOUT_PROGRESS = TIMEOUT_PER_BATCH + 60
    # MISP URI and authentication key
    MISP_URL = ''
    MISP_KEY = getenv('DR_MISP_KEY')
    # MISP feed IDs and target categories
    MISP_FEEDS = {
        'phishtank': ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'phishing'),
        'openphish': ('ffffffff-gggg-hhhh-iiii-jjjjjjjjjjjj', 'phishing')
    }
    # If False, the certificate presented by MISP will not be checked
    MISP_VERIFY_CERTIFICATE = False
