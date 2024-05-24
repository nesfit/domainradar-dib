"""Nested typed dicts defining the shape of the data the collector creates"""
__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

from collections import namedtuple
from datetime import datetime
from typing import List, Dict, TypedDict, Optional


class Domain(TypedDict):
    """Domain data structure for loaders"""
    name: str
    url: Optional[str]
    source: str
    category: str


class Source(TypedDict):
    """Source data structure"""
    url: str
    category: str
    category_source: str
    getter_def: Optional[str]
    mapper_def: Optional[str]


####

# DNS
class IPRecord(TypedDict):
    ttl: int
    value: str


IPFromDNS = namedtuple('IPFromDNS', ['ip', 'source_record_type'])


class CNAMERecord(TypedDict):
    value: str
    related_ips: Optional[List[IPRecord]]


class MXRecord(TypedDict):
    priority: int
    related_ips: Optional[List[IPRecord]]


class NSRecord(TypedDict):
    related_ips: Optional[List[IPRecord]]


class SOARecord(TypedDict):
    primary_ns: str
    resp_mailbox_dname: str
    serial: str
    refresh: int
    retry: int
    expire: int
    min_ttl: int


class RecordsIntMetadata(TypedDict):
    A: int
    AAAA: int
    CNAME: int
    MX: int
    NS: int
    SOA: int
    TXT: int


class DNSSECMetadata(RecordsIntMetadata):
    pass


class RecordSourceMetadata(RecordsIntMetadata):
    pass


class TTLMetadata(RecordsIntMetadata):
    pass


class DNSDataRemarks(TypedDict):
    has_spf: bool
    has_dkim: bool
    has_dmarc: bool
    has_dnskey: bool
    zone_dnskey_selfsign_ok: bool
    zone: str


class DNSData(TypedDict):
    """DNS data structure"""

    dnssec: DNSSECMetadata
    remarks: DNSDataRemarks
    sources: RecordSourceMetadata
    ttls: TTLMetadata

    SOA: Optional[SOARecord]
    zone_SOA: Optional[SOARecord]
    NS: Optional[Dict[str, NSRecord]]
    A: Optional[List[str]]
    AAAA: Optional[List[str]]
    CNAME: Optional[CNAMERecord]
    MX: Optional[Dict[str, MXRecord]]
    TXT: Optional[List[str]]


# Geo
class GeoData(TypedDict):
    """Geolocation data structure"""
    country: Optional[str]
    country_code: Optional[str]
    region: Optional[str]
    region_code: Optional[str]
    city: Optional[str]
    postal_code: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: Optional[str]
    asn: Optional[int]
    as_org: Optional[str]
    isp: Optional[str]
    org: Optional[str]


# ASN
class ASNData(TypedDict):
    asn: Optional[int]
    as_org: Optional[str]
    network_address: Optional[str]
    prefix_len: Optional[int]


# RDAP
class RDAPEntity(TypedDict, total=False):
    """RDAP entity structure (used in the entities list, not a specific query result)"""
    email: str
    handle: str
    name: str
    rir: str
    type: str
    url: str
    whois_server: str


class RDAPBaseData(TypedDict):
    """RDAP result shared data structure"""
    handle: str
    parent_handle: str
    name: str
    whois_server: str
    type: str
    terms_of_service_url: str
    copyright_notice: str
    description: List[str]
    last_changed_date: Optional[datetime]
    registration_date: Optional[datetime]
    expiration_date: Optional[datetime]
    rir: str
    url: str
    entities: Dict[str, List[RDAPEntity]]


class RDAPDomainData(RDAPBaseData):
    """RDAP domain data structure"""
    nameservers: List[str]
    status: List[str]


class IPNetwork(TypedDict):
    """IP network structure"""
    prefix_length: int
    network_address: str
    netmask: str
    broadcast_address: str
    hostmask: str


class RDAPIPData(RDAPBaseData):
    """RDAP IP data structure"""
    country: str
    ip_version: int
    assignment_type: str
    network: IPNetwork


class RDAPASNData(RDAPBaseData):
    """RDAP ASN data structure"""
    asn_range: List[int]


class RDAPEntityData(RDAPBaseData):
    """RDAP entity data structure (extends RDAPBaseData, this is used when you query the RDAP service for
    an entity explicitly)"""
    email: str


# TLS


class CertificateExtension(TypedDict):
    """X.509 Certificate extension structure"""
    critical: bool
    name: str
    value: Optional[str]


class Certificate(TypedDict):
    """Certificate structure"""
    common_name: Optional[str]
    country: Optional[str]
    is_root: bool
    organization: Optional[str]
    valid_len: Optional[int]
    validity_end: Optional[datetime]
    validity_start: Optional[datetime]
    extension_count: int
    extensions: List[CertificateExtension]


class TLSData(TypedDict):
    """TLS data structure for one domain"""
    protocol: str
    cipher: str
    count: int
    certificates: List[Certificate]


class IPRemarks(TypedDict):
    """Remarks for finding unfinished IPs"""
    # dates of last FINISHED evaluation (either OK or not worth retrying)
    rdap_evaluated_on: Optional[datetime]
    asn_evaluated_on: Optional[datetime]
    geo_evaluated_on: Optional[datetime]
    rep_evaluated_on: Optional[datetime]
    icmp_evaluated_on: Optional[datetime]
    is_alive: bool  # if the IP is alive (ICMP ping)
    average_rtt: Optional[float]  # average RTT of ICMP pings


# DB data record


class IPData(TypedDict):
    """Single IP data structure used in the domain structure"""
    ip: str
    from_record: str
    remarks: IPRemarks
    rdap: Optional[RDAPIPData]
    asn: Optional[ASNData]
    geo: Optional[GeoData]
    rep: Optional[Dict[str, Optional[Dict]]]  # reputation data, entries will have arbitrary shape


class DomainRemarks(TypedDict):
    """Remarks for finding unfinished domains"""
    # dates of last FINISHED evaluation (either OK or not worth retrying)
    dns_evaluated_on: Optional[datetime]
    rdap_evaluated_on: Optional[datetime]
    tls_evaluated_on: Optional[datetime]
    # special flag for domains that had no IPs in DNS
    dns_had_no_ips: bool


class DomainData(TypedDict):
    """Single domain main data structure (goes into DB)"""
    domain_name: str
    url: Optional[str]  # url of the domain (if available)
    source: str  # source of the domain (uri of the list, etc.)
    category: str  # category of the domain (malware, phishing, etc.)
    sourced_on: datetime  # when the domain was first added
    evaluated_on: Optional[datetime]  # when the domain was last evaluated
    remarks: DomainRemarks  # info about resolution - dates, failures, etc. (for finding unfinished domains)
    # data
    dns: Optional[DNSData]
    rdap: Optional[RDAPDomainData]
    tls: Optional[TLSData]
    ip_data: Optional[List[IPData]]


def empty_domain_data(domain: Domain) -> DomainData:
    """Returns an empty DomainData structure"""
    return {
        'domain_name': domain['name'],
        'url': domain['url'] if 'url' in domain else None,
        'source': domain['source'],
        'category': domain['category'],
        'sourced_on': datetime.now(),
        'evaluated_on': None,
        'remarks': {
            'dns_evaluated_on': None,
            'rdap_evaluated_on': None,
            'tls_evaluated_on': None,
            'dns_had_no_ips': False
        },
        'dns': None,
        'rdap': None,
        'tls': None,
        'ip_data': None
    }


def empty_ip_data(ip: IPFromDNS) -> IPData:
    """Returns an empty IPData structure"""
    return {
        'ip': ip.ip,
        'from_record': ip.source_record_type,
        'remarks': {
            'rdap_evaluated_on': None,
            'asn_evaluated_on': None,
            'geo_evaluated_on': None,
            'rep_evaluated_on': None,
            'icmp_evaluated_on': None,
            'is_alive': False,
            'average_rtt': None,
        },
        'rdap': None,
        'asn': None,
        'geo': None,
        'rep': None
    }
