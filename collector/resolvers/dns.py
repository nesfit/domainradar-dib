"""Self-contained DNS resolver for the collector"""
__author__ = "Ondřej Ondryáš"

import socket
from typing import Tuple, List, Optional, Literal, Set

import dns.dnssec
import dns.resolver
from dns.message import Message
from dns.name import Name
from dns.rdtypes.ANY.SOA import SOA
from dns.rrset import RRset

import timing
from config import Config
from datatypes import DNSData, IPRecord, SOARecord, CNAMERecord, MXRecord, NSRecord, IPFromDNS
from exceptions import ResolutionImpossible
from logger import logger_resolvers as logger


class DNS:
    NO_RRSIG = 0
    VALID_SELF_SIG = 1
    INVALID_SELF_SIG = 2
    NO_DNS_KEY = 3
    FROM_PRIMARY_NS = 0
    FROM_RESOLVER = 1
    CANNOT_RESOLVE = 2
    _basic_types = ('A', 'AAAA', 'SOA', 'CNAME', 'MX', 'NS', 'TXT')

    def __init__(self):
        self._dns = dns.resolver.Resolver()
        self._dns.nameservers = Config.DNS_SERVERS
        self._dns.lifetime = Config.TIMEOUT

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._udp_sock.setblocking(False)

    def __del__(self):
        self.close_socket()

    def close_socket(self):
        if self._udp_sock:
            self._udp_sock.close()
            self._udp_sock = None

    # query domain for all record types in record_types
    @timing.time_exec
    def query(self, domain_name: str, types: Optional[Tuple[str]] = None) -> Tuple[DNSData, Set[IPFromDNS]]:
        domain = dns.name.from_text(domain_name)
        if types is None:
            types = Config.DNS_RECORD_TYPES

        # Determine the start of authority domain name and the primary nameserver domain name
        try:
            authority_dn, primary_ns_dn, soa = self._find_primary_ns(domain)
        except BaseException as err:
            logger.warning(f"Domain {domain_name} initial SOA resolution error: {str(err)}")
            raise ResolutionImpossible()

        if authority_dn is None:
            logger.warning(f"Domain {domain_name} initial SOA resolution failed")
            raise ResolutionImpossible()

        ret = DNSData(**{'dnssec': {}, 'remarks': {}, 'sources': {}, 'ttls': {},
                         'SOA': None, 'zone_SOA': None, 'NS': None, 'A': None, 'AAAA': None, 'CNAME': None,
                         'MX': None, 'TXT': None})

        # Determine the IP addresses corresponding to the primary NS
        primary_ns_ips = None
        if primary_ns_dn:
            primary_ns_ips = self._find_ip_data(primary_ns_dn)

        # Determine the zone's DNSKEY
        dnskey_rrset = None
        ret['remarks']['has_dnskey'] = False
        ret['remarks']['zone_dnskey_selfsign_ok'] = False

        try:
            dnskey_rrset, key_sig_rrset, _ = self._resolve(authority_dn, 'DNSKEY', primary_ns_ips)
            ret['remarks']['has_dnskey'] = dnskey_rrset is not None and len(dnskey_rrset) != 0
            ret['remarks']['zone_dnskey_selfsign_ok'] = self._validate_signature(authority_dn, dnskey_rrset,
                                                                                 dnskey_rrset, key_sig_rrset)
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            logger.debug(f"No nameservers could resolve DNSKEY for {domain_name}")
        except BaseException as err:
            logger.warning(f"Domain {domain_name} DNSKEY resolution error: {str(err)}")

        ret['remarks']['zone'] = authority_dn.to_text(True)
        ret_ips = set()

        if 'A' in types:
            self._resolve_a_or_aaaa(domain, 'A', primary_ns_ips, dnskey_rrset, ret, ret_ips)
        if 'AAAA' in types:
            self._resolve_a_or_aaaa(domain, 'AAAA', primary_ns_ips, dnskey_rrset, ret, ret_ips)
        if 'SOA' in types:
            self._resolve_soa(domain, primary_ns_ips, dnskey_rrset, ret)
        if 'CNAME' in types:
            self._resolve_cname(domain, primary_ns_ips, dnskey_rrset, ret, ret_ips)
        if 'MX' in types:
            self._resolve_mx(domain, primary_ns_ips, dnskey_rrset, ret, ret_ips)
        if 'NS' in types:
            self._resolve_ns(domain, primary_ns_ips, dnskey_rrset, ret, ret_ips)
        if 'TXT' in types:
            self._resolve_txt(domain, primary_ns_ips, dnskey_rrset, ret)

        for other_type in types:
            if other_type not in DNS._basic_types:
                self._resolve_other(domain, other_type, primary_ns_ips, dnskey_rrset, ret)

        collect_ips_from = Config.COLLECT_IPS_FROM
        filtered_ret_ips = [x for x in ret_ips if x[1] in collect_ips_from]

        # only store "zone SOA" if it's not the actual SOA record resolved and stored for the queried name
        if soa is not None:
            soa_data = DNS._make_soa_data(soa)
            if 'SOA' not in ret or ret['SOA'] != soa_data:
                ret['zone_SOA'] = soa_data

        return ret, set(filtered_ret_ips)

    def _resolve_soa(self, domain: Name, primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData):
        """Resolves a SOA record for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, 'SOA', primary_ns, dnskey, result)
        if data is None:
            return

        if len(data) != 1:
            logger.warning(f"More than one SOA record for {domain}")

        soa_rec = data[0]  # type: SOA
        result['SOA'] = DNS._make_soa_data(soa_rec)

    def _resolve_a_or_aaaa(self, domain: Name, record_type: Literal['A', 'AAAA'],
                           primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData, ips: Set[IPFromDNS]):
        """Resolves an A or AAAA record set for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, record_type, primary_ns, dnskey, result)
        if data is None:
            return

        result[record_type] = []
        for a_record in data:  # type: dns.rdtypes.IN.A.A
            result[record_type].append(a_record.address)
            ips.add(IPFromDNS(a_record.address, record_type))

    def _resolve_cname(self, domain: Name, primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData,
                       ips: Set[IPFromDNS]):
        """Resolves a CNAME record for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, 'CNAME', primary_ns, dnskey, result)
        if data is None:
            return

        if len(data) > 1:
            logger.warning(f"Multiple CNAME records for {domain}")

        value = data[0].target  # type: Name
        related_ips = self._find_ip_data(value)
        result['CNAME'] = CNAMERecord(value=value.to_text(True), related_ips=related_ips)
        for related_ip in related_ips:
            ips.add(IPFromDNS(related_ip['value'], 'CNAME'))

    def _resolve_mx(self, domain: Name, primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData,
                    ips: Set[IPFromDNS]):
        """Resolves an MX record set for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, 'MX', primary_ns, dnskey, result)
        if data is None:
            return

        result['MX'] = {}
        for mx_record in data:  # type: dns.rdtypes.ANY.MX.MX
            related_ips = self._find_ip_data(mx_record.exchange)
            result['MX'][mx_record.exchange.to_text(True)] = MXRecord(priority=mx_record.preference,
                                                                      related_ips=related_ips)
            for related_ip in related_ips:
                ips.add(IPFromDNS(related_ip['value'], 'MX'))

    def _resolve_ns(self, domain: Name, primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData,
                    ips: Set[IPFromDNS]):
        """Resolves a NS record set for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, 'NS', primary_ns, dnskey, result)
        if data is None:
            return

        result['NS'] = {}
        for ns_record in data:  # type: dns.rdtypes.ANY.NS.NS
            related_ips = self._find_ip_data(ns_record.target)
            result['NS'][ns_record.target.to_text(True)] = NSRecord(related_ips=related_ips)
            for related_ip in related_ips:
                ips.add(IPFromDNS(related_ip['value'], 'NS'))

    def _resolve_txt(self, domain: Name, primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData):
        """
        Resolves a TXT record set for a given domain name and populates a result object.
        Checks the TXT records for known values, such as SPF, DKIM and DMARC control strings.
        """
        data = self._resolve_record_base(domain, 'TXT', primary_ns, dnskey, result)
        if data is None:
            return

        result['TXT'] = []

        for txt_record in data:  # type: dns.rdtypes.ANY.TXT.TXT
            for string in txt_record.strings:
                try:
                    text_orig = string.decode()
                except UnicodeDecodeError as ude:
                    logger.error(f"TXT decoding error for {domain}", exc_info=ude)
                    continue

                text = text_orig.lower()
                if "v=spf1" in text:
                    result['remarks']['has_spf'] = True
                if "v=dkim1" in text:
                    result['remarks']['has_dkim'] = True
                if "v=dmarc1" in text:
                    result['remarks']['has_dmarc'] = True
                result['TXT'].append(text)

    # noinspection PyTypedDict
    def _resolve_other(self, domain: Name, record_type: str, primary_ns: List[IPRecord], dnskey: Optional[RRset],
                       result: DNSData):
        """Resolves an arbitrary record type set for a given domain name and populates a result object."""
        data = self._resolve_record_base(domain, record_type, primary_ns, dnskey, result)
        if data is None:
            return

        result[record_type] = []
        for record in data:  # type: RRset
            result[record_type].append(record.to_text())

    # noinspection PyTypedDict
    def _resolve_record_base(self, domain: Name, record_type: str,
                             primary_ns: List[IPRecord], dnskey: Optional[RRset], result: DNSData) -> Optional[RRset]:
        """
        Common base for record resolving. Populates the corresponding DNSSEC, TTL and source of resolution metadata
        values in a result object. Consumes exceptions, returns None when there's an error, the resulting RRset
        doesn't match the queried domain name or when it's empty.
        """
        # default values
        result['dnssec'][record_type] = DNS.NO_DNS_KEY if dnskey is None else DNS.INVALID_SELF_SIG
        result['sources'][record_type] = DNS.CANNOT_RESOLVE
        result['ttls'][record_type] = 0

        # noinspection PyBroadException
        try:
            data, _, from_primary, validity = self._resolve_and_validate(domain, record_type, primary_ns, dnskey)
            if data.name != domain:
                return None

            result['dnssec'][record_type] = validity
            result['sources'][record_type] = DNS.FROM_PRIMARY_NS if from_primary else DNS.FROM_RESOLVER
            result['ttls'][record_type] = data.ttl

            if len(data) == 0:
                return None

            return data
        except Exception:
            return None

    def _resolve_and_validate(self, domain: Name, record_type: str, primary_ns: Optional[List[IPRecord]],
                              dnskey: Optional[RRset]) -> Tuple[Optional[RRset], Optional[RRset], bool, int]:
        """
        Queries a record set of a given type for a domain. If a DNSKEY is provided and a RRSIG has been retrieved,
        verifies the signature. Only verifies the RRset signature against the given DNSKEY, doesn't check the whole
        signature chain.
        Returns a tuple of (queried RRset for the record type, RRSIG RRset,
        bool signalising if the record has been resolved from the primary nameserver, one of
        NO_RRSIG/VALID_SELF_SIG/INVALID_SELF_SIG).
        """
        data, sig, from_primary = self._resolve(domain, record_type, primary_ns)
        if data is None:
            return None, None, False, DNS.NO_RRSIG
        if dnskey is None or len(dnskey) == 0:
            return data, sig, from_primary, DNS.NO_DNS_KEY
        if sig is None:
            return data, sig, from_primary, DNS.NO_RRSIG
        if self._validate_signature(domain, dnskey, data, sig):
            return data, sig, from_primary, DNS.VALID_SELF_SIG
        else:
            return data, sig, from_primary, DNS.INVALID_SELF_SIG

    @timing.time_exec
    def _resolve(self, domain: Name, record_type: str, primary_ns: Optional[List[IPRecord]]) -> \
            Tuple[Optional[RRset], Optional[RRset], bool]:
        """
        Queries a record set of a given type for a domain. Tries to use provided IP addresses of the primary nameserver.
        When a query to a primary NS fails, the address is removed from the provided list. When no addresses are left,
        uses dnspython's stub resolver with the globally configured DNS server address(es).
        """

        def resolve_fallback() -> Tuple[RRset, Optional[RRset]]:
            answer = self._dns.resolve(domain, record_type)
            return get_response_pair(answer.response)

        # noinspection PyShadowingNames
        def get_response_pair(response: Message) -> Tuple[RRset, Optional[RRset]]:
            """Extracts the RRset bearing the queried data, and the signature RRset"""
            record_type_num = dns.rdatatype.from_text(record_type)
            data_set = None
            rrsig_set = None

            for rrset in response.answer:
                if rrset.rdtype == record_type_num:
                    data_set = rrset
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    rrsig_set = rrset

            if data_set is None:
                raise KeyError(f"{record_type} record not found")

            return data_set, rrsig_set

        fallback = False
        if primary_ns is None or len(primary_ns) == 0:
            fallback = True

        while not fallback:
            ns_to_try = primary_ns[0]
            query = dns.message.make_query(domain, record_type, use_edns=True, want_dnssec=True)
            # noinspection PyBroadException
            try:
                response, _ = dns.query.udp_with_fallback(query, ns_to_try['value'], Config.TIMEOUT,
                                                          udp_sock=self._udp_sock)
                res_data, res_sig = get_response_pair(response)
                return res_data, res_sig, True
            except KeyError:
                logger.debug(f"Record {record_type} not found for {domain} using primary NS {ns_to_try['value']}")
                fallback = True
            except Exception:
                logger.info(f"Primary NS {ns_to_try['value']} for {domain} deemed unreachable.")
                del primary_ns[0]
                if len(primary_ns) == 0:
                    fallback = True

        try:
            res_data, res_sig = resolve_fallback()
            return res_data, res_sig, False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            return None, None, False

    @timing.time_exec
    def _find_primary_ns(self, domain: Name) -> Tuple[Optional[Name], Optional[Name], Optional[SOA]]:
        """Attempts to find the containing zone name and the primary nameserver for a given domain name."""

        def get_authority():
            if len(message.authority) == 0:
                return None, None, None
            authority_rrset = message.authority[0]
            # noinspection PyShadowingNames
            soa_recs = [a for a in authority_rrset if isinstance(a, SOA)]
            if len(soa_recs) == 0:
                return authority_rrset.name, None, None
            return authority_rrset.name, soa_recs[0].mname, soa_recs[0]

        try:
            # Resolve a SOA record for the domain using the internal resolver
            answer = self._dns.resolve(domain, dns.rdatatype.SOA)
            # Find the first SOA record (you never know what the message may contain)
            soa_recs = [a for a in answer.rrset if isinstance(a, SOA)]
            if len(soa_recs) == 0:
                return answer.rrset.name, None, None
            return answer.rrset.name, soa_recs[0].mname, soa_recs[0]
        except dns.resolver.NXDOMAIN as err:
            # The domain doesn't exist, or it isn't a zone
            # Try looking up the 'best' SOA record in the message's AUTHORITY field
            responses = err.responses()
            if len(responses) == 0:
                possible_result = None, None, None
            else:
                _, message = responses.popitem()
                possible_result = get_authority()
        except dns.resolver.NoAnswer as err:
            message = err.response()
            possible_result = get_authority()
        except dns.exception.Timeout:
            logger.info(f"Resolver timeout when finding primary NS for {domain}")
            return None, None, None

        # If the current DN is second-level or top-level, return the 'best' non-answer found record
        # (this may be None, None)
        if len(domain) <= 3:
            return possible_result

        # Otherwise cut off the highest-level part of the DN a try again
        more_general_name = domain.split(len(domain) - 1)[1]
        return self._find_primary_ns(more_general_name)

    @timing.time_exec
    # noinspection PyBroadException
    def _find_ip_data(self, domain: Name) -> List[IPRecord]:
        """Resolves all A/AAAA records for a given domain name."""
        ret = []
        try:
            a = self._dns.resolve(domain, 'A')
            for rrset in a.response.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    for record in rrset:
                        ret.append(IPRecord(ttl=rrset.ttl, value=record.address))
        except Exception as err:
            logger.debug(f"Cannot find IPv4 data for {domain}: {str(err)}")

        try:
            aaaa = self._dns.resolve(domain, 'AAAA')
            for rrset in aaaa.response.answer:
                if rrset.rdtype == dns.rdatatype.AAAA:
                    for record in rrset:
                        ret.append(IPRecord(ttl=rrset.ttl, value=record.address))
        except Exception as err:
            logger.debug(f"Cannot find IPv6 data for {domain}: {str(err)}")

        return ret

    @staticmethod
    def _validate_signature(domain: Name, dnskey: RRset, data: RRset, rrsig: Optional[RRset]):
        if rrsig is None:
            return False
        try:
            dns.dnssec.validate(data, rrsig, {dnskey.name: dnskey})
            return True
        except dns.dnssec.ValidationFailure:
            logger.debug(f"DNSSEC validation error for {domain} / {data.rdtype}")
            return False

    @staticmethod
    def _make_soa_data(soa_rec: SOA) -> SOARecord:
        return SOARecord(primary_ns=soa_rec.mname.to_text(True),
                         resp_mailbox_dname=soa_rec.rname.to_text(True), serial=soa_rec.serial,
                         refresh=soa_rec.refresh, retry=soa_rec.retry, expire=soa_rec.expire,
                         min_ttl=soa_rec.minimum)
