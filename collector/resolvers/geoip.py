__author__ = "Adam Horák"

from typing import List

import geoip2.database
import geoip2.errors
import geoip2.models

import timing
from datatypes import GeoData
from exceptions import *


def default_mapper(data: geoip2.models.City) -> GeoData:
    """
    Default mapping function for geolocation data from ip-api.com
    Takes the reader result and maps the fields to a GeoData object
    """
    return {
        "country": data.country.name,
        "country_code": data.country.iso_code,
        "region": data.subdivisions.most_specific.name,
        "region_code": data.subdivisions.most_specific.iso_code,
        "city": data.city.name,
        "postal_code": data.postal.code,
        "latitude": data.location.latitude,
        "longitude": data.location.longitude,
        "timezone": data.location.time_zone,
        "isp": data.traits.isp,
        "org": data.traits.organization
    }


class Geo:
    def __init__(self):
        self._reader = geoip2.database.Reader("data/geolite/GeoLite2-City.mmdb")

    def __del__(self):
        if self._reader:
            self._reader.close()

    @timing.time_exec
    def query(self, ips: List[str]) -> List[GeoData]:
        """Query the API for geolocation data for a list of IPs"""
        result = []
        for ip in ips:
            try:
                result.append(default_mapper(self._reader.city(ip)))
            except geoip2.errors.AddressNotFoundError:
                raise ResolutionImpossible
        return result

    def single(self, ip: str) -> GeoData:
        """Query the API for geolocation data for a single IP"""
        return self.query([ip])[0]
