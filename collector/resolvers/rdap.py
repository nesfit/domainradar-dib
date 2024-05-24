"""Self-contained RDAP/WHOIS resolver for the collector, wraps whoisit module with auto bootstrapping and falls back to
whois if needed"""
__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

import json
import re
from typing import Optional

import tldextract
import whoisdomain as whois
import whoisit
from whoisit.errors import BootstrapError

import timing
from config import Config
from datatypes import RDAPDomainData, RDAPIPData, IPNetwork
from exceptions import *
from logger import logger_resolvers as logger


class RDAP:
    def __init__(self):
        if not whoisit.is_bootstrapped():
            load_bootstrap_data()

        whoisit.utils.http_timeout = Config.TIMEOUT
        whoisit.utils.http_max_retries = 2
        whoisit.utils.http_pool_maxsize = 32
        whoisit.utils.http_pool_connections = 32

    @timing.time_exec
    def domain(self, domain: str, **kwargs) -> Optional[RDAPDomainData]:
        original_domain = domain

        def worker(current_domain):
            try:
                return whoisit.domain(current_domain, **kwargs)
            except whoisit.errors.UnsupportedError:
                logger.info(f"No RDAP endpoint for {current_domain}")
            except whoisit.errors.RateLimitedError:
                logger.warning(f"RDAP rate limited for {current_domain}")
            except whoisit.errors.ResourceDoesNotExist:
                logger.info(f"RDAP resource doesn't exist: {current_domain}")
            except whoisit.errors.QueryError as e:
                logger.info(f"RDAP status code error for {current_domain}: {str(e)}")
            except Exception as e:
                logger.error(f'RDAP error for {current_domain}', exc_info=e)

            try:
                return self._query_whois(current_domain)
            except (ResolutionNeedsRetry, ResolutionImpossible) as e:
                err = e

            extracted = tldextract.extract(current_domain)
            if len(extracted.subdomain) == 0:
                raise err

            more_general_name = extracted.registered_domain
            logger.info(f"Trying more general name {more_general_name} for {original_domain}")

            return worker(more_general_name)

        return worker(domain)

    @staticmethod
    def _query_whois(domain: str) -> Optional[RDAPDomainData]:
        try:
            logger.info(f'Trying whois fallback for {domain}')
            w = whois.query(domain, timeout=float(Config.TIMEOUT))
            if w is not None:
                return whois_to_rdap_domain(w)
        except whois.exceptions.WhoisQuotaExceeded:
            logger.error(f'Whois quota exceeded (at {domain})')
            raise ResolutionNeedsRetry()
        except whois.exceptions.UnknownTld:
            logger.info(f'Unknown TLD for {domain}')
            raise ResolutionImpossible()
        except whois.exceptions.WhoisPrivateRegistry:
            logger.warning(f'Whois private registry for {domain}')
            raise ResolutionImpossible()
        except (whois.exceptions.WhoisCommandTimeout, whois.exceptions.WhoisCommandFailed):
            logger.warning(f'Whois timeout/fail for {domain}')
            raise ResolutionNeedsRetry()
        except whois.exceptions.FailedParsingWhoisOutput:
            logger.warning(f'Invalid whois output for {domain}')
            raise ResolutionImpossible()
        except Exception as e:
            logger.error(f'Whois query for {domain} failed', exc_info=e)
            raise ResolutionImpossible()

        logger.info(f'Whois empty for {domain}')
        raise ResolutionImpossible()

    @timing.time_exec
    def ip(self, ip: str, **kwargs) -> Optional[RDAPIPData]:
        # raises ResourceDoesNotExist if not found
        try:
            ipdata = whoisit.ip(ip, **kwargs)
            ipdata['network'] = IPNetwork(
                prefix_length=ipdata['network'].prefixlen,
                network_address=str(ipdata['network'].network_address),
                netmask=str(ipdata['network'].netmask),
                broadcast_address=str(ipdata['network'].broadcast_address),
                hostmask=str(ipdata['network'].hostmask)
            )
            return RDAPIPData(**ipdata)
        except whoisit.errors.RateLimitedError:
            raise ResolutionNeedsRetry
        except BaseException:
            raise ResolutionImpossible


def save_bootstrap_data():
    bootstrap_data = whoisit.save_bootstrap_data()
    with open('data/rdap_bootstrap.json', 'w') as f:
        json.dump(bootstrap_data, f)


def bootstrap():
    whoisit.clear_bootstrapping()
    whoisit.bootstrap(overrides=True)
    save_bootstrap_data()


def load_bootstrap_data():
    try:
        with open('data/rdap_bootstrap.json', 'r') as f:
            bootstrap_data = json.load(f)
            whoisit.load_bootstrap_data(bootstrap_data, overrides=True)
            logger.info('Loaded RDAP bootstrap data from file')
            if whoisit.bootstrap_is_older_than(3):
                logger.info('Bootstrap data is older than 3 days, bootstrapping...')
                bootstrap()
    except IOError:
        bootstrap()
    except BootstrapError:
        logger.warning('Multiple bootstrap requests (concurrency issue)')


# WHOIS fallback helpers


def definitely_string(s) -> str:
    if s is None:
        return ''
    return str(s)


def normal_case(string: str):
    result = re.sub('([A-Z])', r' \1', string)
    return result.lower()


def whois_to_rdap_domain(d: whois.Domain) -> RDAPDomainData:
    return RDAPDomainData(
        handle='',
        parent_handle='',
        name=d.name,
        whois_server='',
        type='domain',
        terms_of_service_url='',
        copyright_notice='',
        description=[],
        last_changed_date=d.last_updated,
        registration_date=d.creation_date,
        expiration_date=d.expiration_date,
        rir='',
        url='',
        entities={
            'registrant': [{
                'name': definitely_string(d.registrant) if hasattr(d, 'registrant') else ''
            }],
            'abuse': [{
                'email': definitely_string(d.abuse_contact) if hasattr(d, 'abuse_contact') else ''
            }],
            'admin': [{
                'name': definitely_string(d.admin) if hasattr(d, 'admin') else ''
            }],
            'registrar': [{
                'name': definitely_string(d.registrar) if hasattr(d, 'registrar') else ''
            }]
        },
        nameservers=[n.upper() for n in d.name_servers],
        status=list(dict.fromkeys([normal_case(status.split()[0]) for status in d.statuses]))
    )
