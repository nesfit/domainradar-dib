"""ASN information resolver based on the GeoLite2 ASN database"""
__author__ = ["Ondřej Ondryáš", "Adam Horák"]

from typing import List

import geoip2.database
import geoip2.errors
import geoip2.models

import timing
from datatypes import ASNData
from exceptions import *


def default_mapper(data: geoip2.models.ASN) -> ASNData:
    return ASNData(asn=data.autonomous_system_number, as_org=data.autonomous_system_organization,
                   network_address=str(data.network.network_address), prefix_len=data.network.prefixlen)


class ASN:
    def __init__(self):
        self._reader = geoip2.database.Reader("data/geolite/GeoLite2-ASN.mmdb")

    def __del__(self):
        self._reader.close()

    @timing.time_exec
    def query(self, ips: List[str]) -> List[ASNData]:
        """Query the database for ASN data for a list of IPs"""
        result = []
        for ip in ips:
            try:
                result.append(default_mapper(self._reader.asn(ip)))
            except geoip2.errors.AddressNotFoundError:
                raise ResolutionImpossible
        return result

    def single(self, ip: str) -> ASNData:
        """Query the database for ASN data for a single IP"""
        return self.query([ip])[0]
