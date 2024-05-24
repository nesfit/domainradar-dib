__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

from datetime import datetime
# import all resolvers
from threading import Event
from typing import Literal

import config
import timing
from datatypes import DomainData, empty_ip_data, IPFromDNS
# import other stuff for main resolver
from exceptions import *
from logger import logger
from mongo import MongoWrapper
from .asn import ASN
from .dns import DNS
from .geoip import Geo as GeoIP2
from .icmp import ICMP
from .rdap import RDAP
from .tls import TLS


# noinspection PyBroadException
@timing.time_exec
def resolve_domain(cancel_event: Event, domain: DomainData, domain_index: int, mongo: MongoWrapper,
                   mode: str = 'basic', retry_evaluated=False):
    """Resolve domain basic info and store results in db"""
    name = domain['domain_name']
    logger.info(f"Resolving {name} (#{domain_index})")

    if mode == 'basic':
        rdap = RDAP()
        tls = TLS()

        # resolve DNS if needed
        if retry_evaluated or domain['remarks']['dns_evaluated_on'] is None:
            logger.info(f"Resolving DNS for {name} (#{domain_index})")
            dns = DNS()
            try:
                domain['remarks']['dns_evaluated_on'] = datetime.now()
                domain['dns'], ips = dns.query(name)
                domain['remarks']['dns_had_no_ips'] = ips is None or len(ips) == 0
                if ips is not None and len(ips) > 0:
                    if domain['ip_data'] is None:
                        domain['ip_data'] = []
                    for ip in ips:
                        if not any(ip_data['ip'] == ip.ip for ip_data in domain['ip_data']):
                            domain['ip_data'].append(empty_ip_data(ip))
            except ResolutionImpossible:
                domain['dns'] = None
                domain['remarks']['dns_had_no_ips'] = False
            except ResolutionNeedsRetry:
                domain['remarks']['dns_evaluated_on'] = None
            except BaseException as err:
                domain['dns'] = None
                domain['remarks']['dns_evaluated_on'] = None
                logger.error(f"DNS resolver uncaught error for {name}", exc_info=err)
            dns.close_socket()

        if cancel_event.is_set():
            return

        # resolve RDAP if needed
        if retry_evaluated or domain['remarks']['rdap_evaluated_on'] is None:
            logger.info(f"Resolving RDAP for {name} (#{domain_index})")
            try:
                domain['remarks']['rdap_evaluated_on'] = datetime.now()
                domain['rdap'] = rdap.domain(name)
            except ResolutionImpossible:
                domain['rdap'] = None
            except ResolutionNeedsRetry:
                domain['remarks']['rdap_evaluated_on'] = None
            except BaseException as err:
                domain['rdap'] = None
                domain['remarks']['rdap_evaluated_on'] = None
                logger.error(f"RDAP resolver uncaught error for {name}", exc_info=err)

        if cancel_event.is_set():
            return

        # resolve TLS if needed
        if retry_evaluated or domain['remarks']['tls_evaluated_on'] is None:
            logger.info(f"Resolving TLS for {name} (#{domain_index})")
            try:
                domain['remarks']['tls_evaluated_on'] = datetime.now()
                domain['tls'] = tls.resolve(name)
            except ResolutionImpossible:
                domain['tls'] = None
            except ResolutionNeedsRetry:
                # immediately retry for timeouts, last chance
                try:
                    domain['tls'] = tls.resolve(name, timeout=2)
                except BaseException:  # anything
                    domain['tls'] = None
                    domain['remarks']['tls_evaluated_on'] = None
            except BaseException as err:
                domain['tls'] = None
                domain['remarks']['tls_evaluated_on'] = None
                logger.error(f"TLS resolver uncaught error for {name}", exc_info=err)

        if cancel_event.is_set():
            return

        # resolve IP RDAP and alive status if needed
        if domain['ip_data'] is not None:
            logger.info(f"Resolving IP data for {name} (#{domain_index})")
            for ip_data in domain['ip_data']:
                ip_val = ip_data['ip']
                # resolve RDAP
                if retry_evaluated or ip_data['remarks']['rdap_evaluated_on'] is None:
                    logger.debug(f"Resolving RDAP for {ip_val} (#{domain_index})")
                    try:
                        ip_data['rdap'] = rdap.ip(ip_val)
                        ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['rdap'] = None
                        ip_data['remarks']['rdap_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['rdap_evaluated_on'] = None
                    except BaseException as err:
                        domain['rdap'] = None
                        domain['remarks']['rdap_evaluated_on'] = None
                        logger.error(f"RDAP resolver uncaught error for {ip_val}", exc_info=err)

                if cancel_event.is_set():
                    return

        # mark evaluated time
        domain['evaluated_on'] = datetime.now()

    elif mode == 'geo':
        geo = GeoIP2()
        asn = ASN()

        if domain['ip_data'] is not None:
            for ip_data in domain['ip_data']:
                ip_val = ip_data['ip']

                if retry_evaluated or ip_data['remarks']['geo_evaluated_on'] is None:
                    logger.debug(f"Resolving GEO for {ip_val} (#{domain_index})")
                    try:
                        ip_data['geo'] = geo.single(ip_val)
                        ip_data['remarks']['geo_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['geo'] = None
                        ip_data['remarks']['geo_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['geo_evaluated_on'] = None

                if cancel_event.is_set():
                    return

                # resolve ASN information
                if retry_evaluated or 'asn_evaluated_on' not in ip_data['remarks'] or \
                        ip_data['remarks']['asn_evaluated_on'] is None:
                    logger.debug(f"Resolving ASN for {ip_val} (#{domain_index})")
                    try:
                        ip_data['asn'] = asn.single(ip_val)
                        ip_data['remarks']['asn_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['asn'] = None
                        ip_data['remarks']['asn_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['asn_evaluated_on'] = None

                if cancel_event.is_set():
                    return

    elif mode == 'icmp':
        icmp = ICMP()
        if domain['ip_data'] is not None:
            logger.info(f"Resolving IP/ICMP for {name} (#{domain_index})")

            for ip_data in domain['ip_data']:
                ip_val = ip_data['ip']
                # resolve alive status
                if retry_evaluated or ip_data['remarks']['icmp_evaluated_on'] is None:
                    logger.debug(f"Pinging {ip_val} (#{domain_index})")
                    try:
                        ip_data['remarks']['is_alive'], ip_data['remarks']['average_rtt'] = icmp.ping(ip_val)
                        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
                    except ResolutionImpossible:
                        ip_data['remarks']['is_alive'] = False
                        ip_data['remarks']['icmp_evaluated_on'] = datetime.now()
                    except ResolutionNeedsRetry:
                        ip_data['remarks']['icmp_evaluated_on'] = None

                if cancel_event.is_set():
                    return

    logger.info(f"Domain {name} (#{domain_index}) done")
    # store results
    mongo.store(domain)


def update_ips(domain: DomainData, domain_index: int, mongo: MongoWrapper):
    dns_data = domain['dns']
    if dns_data is None or domain['remarks']['dns_evaluated_on'] is None:
        return

    name = domain['domain_name']
    logger.info(f"Checking {name} (#{domain_index})")

    ips = []

    rec_type: Literal['A', 'AAAA', 'CNAME', 'MX', 'NS']
    for rec_type in config.Config.COLLECT_IPS_FROM:
        if rec_type in dns_data and dns_data[rec_type] is not None:
            rec = dns_data[rec_type]
            if rec_type == 'A' or rec_type == 'AAAA':
                ips.extend(IPFromDNS(x, rec_type) for x in rec)
            elif rec_type == 'CNAME' and 'related_ips' in rec and rec['related_ips'] is not None:
                ips.extend(IPFromDNS(x['value'], rec_type) for x in rec['related_ips'])
            elif rec_type == 'MX' or rec_type == 'NS':
                for v in rec.values():
                    if 'related_ips' in v and v['related_ips'] is not None:
                        ips.extend(IPFromDNS(x['value'], rec_type) for x in v['related_ips'])

    if len(ips) == 0:
        return

    ip_data = (domain['ip_data'] if 'ip_data' in domain else []) or []
    found_set = set()
    for existing_ip in ip_data:
        found_set.add(existing_ip['ip'])

    written = 0
    for ip in ips:
        if ip.ip not in found_set:
            ip_data.append(empty_ip_data(ip))
            written += 1
            found_set.add(ip.ip)

    logger.info(f"[#{domain_index}] Wrote {written} IPs")
    domain['ip_data'] = ip_data
    # store results
    mongo.store(domain)
