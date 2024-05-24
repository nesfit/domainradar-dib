"""
Domain name loader - reads a file with domain names... that's it
File in -> List of domain names
"""
__author__ = "Adam Horák"

import re
from typing import List

from datatypes import Domain
from loaders.utils import LoaderUtils as Utils
from logger import logger


class DirectLoader:
    """Local file data loader for the collector"""
    valid_sources = ("plain", "octet-stream", "html", "csv")

    def __init__(self, file: str, category: str, tmp_dir="tmp"):
        self._tmp_dir = tmp_dir
        self._category = category
        self._source = file

    def load(self):
        """A generator that just yields the domains found (generator is used for consistency with other loaders)"""
        domain_names: List[Domain] = []
        with open(self._source, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith(Utils.comment_prefixes) or len(line) == 0:
                    continue
                domain = re.search(Utils.hostname_regex, line)
                if domain:
                    dom_name = domain.group(0)  # type: str
                    domain_names.append({
                        'name': dom_name,
                        'url': line,
                        'source': self._source,
                        'category': self._category,
                    })
            logger.info("Loaded " + str(len(domain_names)) + " domains from " + self._source)
            yield domain_names
