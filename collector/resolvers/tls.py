"""TLS resolver with X.509 extension reader"""
__authors__ = ["Jan Polišenský", "Adam Horák", "Ondřej Ondryáš"]

import datetime
import socket
import time
from typing import List

import OpenSSL.SSL
from OpenSSL.crypto import X509

import timing
from config import Config
from datatypes import TLSData, Certificate, CertificateExtension
from exceptions import *
from logger import logger_resolvers as logger


class TLS:
    def __init__(self, timeout=Config.TIMEOUT):
        self.timeout = timeout

    #
    @staticmethod
    def _download(host: str, port: int = 443):
        """Download TLS certificate chain from host:port"""
        result = {}

        sock_int = None

        try:
            sock_int = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_int.settimeout(Config.TLS_TIMEOUT)
            sock_int.setblocking(False)

            ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
            ctx.set_timeout(Config.TLS_TIMEOUT)

            sock = OpenSSL.SSL.Connection(context=ctx, socket=sock_int)
            for i in range(Config.TLS_NONBLOCKING_RETRIES):
                try:
                    sock.connect((host, port))
                    break
                except OSError:
                    time.sleep(Config.TLS_TIMEOUT / Config.TLS_NONBLOCKING_RETRIES)
            else:
                raise ResolutionImpossible

            sock.set_connect_state()
            sock.set_tlsext_host_name(str.encode(host))

            for i in range(Config.TLS_NONBLOCKING_RETRIES):
                try:
                    sock.do_handshake()
                    break
                except OpenSSL.SSL.WantReadError:
                    time.sleep(Config.TLS_TIMEOUT / Config.TLS_NONBLOCKING_RETRIES)
            else:
                raise ResolutionImpossible

            result["cipher_name"] = sock.get_cipher_name()
            chain = sock.get_verified_chain()
            result["chain_len"] = len(chain) if chain else 0
            result["protocol"] = sock.get_protocol_version_name()
            result["cert_chain"] = chain
        except socket.gaierror as e:
            logger.error(f"{host} TLS: cannot resolve domain name or connection error: {str(e)}")
            raise ResolutionImpossible
        except socket.timeout:
            logger.error(f"{host} TLS: socket timeout")
            raise ResolutionNeedsRetry
        except OpenSSL.SSL.Error as e:
            logger.error(f"{host} TLS: cannot find any root certificates: {str(e)}")
            raise ResolutionImpossible
        except ConnectionRefusedError:
            logger.error(f"{host} TLS: connection refused")
            raise ResolutionImpossible
        except (ResolutionNeedsRetry, ResolutionImpossible):
            raise
        except BaseException as e:
            logger.error(f"{host} TLS: general error", exc_info=e)
            raise ResolutionNeedsRetry
        finally:
            try:
                if sock_int is not None:
                    sock_int.close()
            except BaseException as err:
                logger.error(f"{host} TLS: Error during OpenSSL connection closing", exc_info=err)

        return result

    #
    @staticmethod
    def _parse_certificate(cert: X509, is_root=False):
        """Parse certificate and return Certificate object"""
        # Parse validity
        valid_from_raw = cert.get_notBefore()
        valid_to_raw = cert.get_notAfter()
        if valid_from_raw is None or valid_to_raw is None:
            logger.error(f"TLS: Certificate validity is None")
            valid_from = None
            valid_to = None
            validity_len = None
        else:
            valid_to = datetime.datetime.strptime(valid_to_raw.decode("utf-8")[:-1], "%Y%m%d%H%M%S")
            valid_from = datetime.datetime.strptime(valid_from_raw.decode("utf-8")[:-1], "%Y%m%d%H%M%S")
            validity_len = int((valid_to - valid_from).total_seconds())

        # Parse issuer info
        attributes = str(cert.get_issuer()).split('/')
        common_name = None
        organization = None
        country = None
        for attr in attributes:
            split = attr.split('=')
            if split[0] == 'CN':
                common_name = split[1]
            elif split[0] == 'O':
                organization = split[1]
            elif split[0] == 'C':
                country = split[1]

        # Parse extensions
        extensions: List[CertificateExtension] = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            # noinspection PyBroadException
            try:
                val = str(ext)
            except BaseException:
                val = None
            extensions.append({
                "critical": ext.get_critical(),
                "name": ext.get_short_name().decode("utf-8"),
                "value": val
            })

        return Certificate(
            common_name=common_name,
            organization=organization,
            country=country,
            validity_start=valid_from,
            validity_end=valid_to,
            valid_len=validity_len,
            extensions=extensions,
            extension_count=len(extensions),
            is_root=is_root
        )

    #
    def _parse_chain(self, chain: List[X509]):
        """Parse certificate chain and return list of Certificate objects"""
        result: List[Certificate] = []
        for i, cert in enumerate(chain):
            result.append(self._parse_certificate(cert, i == len(chain) - 1))
        return result

    #
    @timing.time_exec
    def resolve(self, host: str, port: int = 443, timeout: int = Config.TIMEOUT):
        """Resolve TLS data from host:port"""
        self.timeout = timeout
        try:
            data = self._download(host, port)
            return None if data is None else TLSData(
                cipher=data["cipher_name"],
                count=data["chain_len"],
                protocol=data["protocol"],
                certificates=self._parse_chain(data["cert_chain"])
            )
        except BaseException:
            raise ResolutionImpossible
