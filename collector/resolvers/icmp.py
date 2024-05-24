"""Self-contained ping resolver for the pong collector to see if host is alive"""
__author__ = "Adam Horák"

import sys
from typing import Tuple

from icmplib import ping
from icmplib.exceptions import NameLookupError, SocketAddressError, SocketPermissionError

import timing
from config import Config
from exceptions import *
from logger import logger_resolvers as logger


class ICMP:
    def __init__(self, count=1, interval=1, timeout=Config.TIMEOUT, privileged=Config.ICMP_PRIVILEGED):
        self._count = count
        self._interval = interval
        self._timeout = timeout
        self._privileged = privileged

    @timing.time_exec
    def ping(self, address: str) -> Tuple[bool, float]:
        """Ping a single host and return (is_alive, avg_rtt)"""
        try:
            result = ping(address, count=self._count, interval=self._interval, timeout=self._timeout,
                          privileged=self._privileged)
            return result.is_alive, result.avg_rtt
        except SocketPermissionError:
            print("ICMP: No permission to create raw socket!", file=sys.stderr)
            raise ResolutionNeedsRetry
        except (NameLookupError, SocketAddressError) as e:
            logger.error("Error during ping: " + str(e))
            raise ResolutionNeedsRetry
        except BaseException as e:
            logger.error("Error during ping", exc_info=e)
            raise ResolutionImpossible
