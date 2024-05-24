"""
Domain name loader - reads a file with source URIs and loads domain names from them
File in -> List of source file URIs -> Download each file -> Extract domain names -> List of domain names
"""
__author__ = "Adam Horák"

import csv
import os
import re
import urllib.error
import urllib.request
import zipfile
from typing import List

from datatypes import Domain, Source
from loaders.utils import LoaderUtils as Utils, create_getter, create_mapper
from logger import logger


class SourceLoader:
    """Remote data loader for the collector"""
    valid_sources = ("plain", "octet-stream", "html", "csv", "zip")

    def __init__(self, tmp_dir="tmp"):
        self.tmp_dir = tmp_dir
        self.sources: List[Source] = []

    def source_plain(self, filename: str):
        """Reads the file as plain text and looks for non-empty lines that are not comments"""
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith(Utils.comment_prefixes) or len(line) == 0:
                    continue
                self.sources.append({
                    'url': line,
                    'category': 'unknown',
                    'category_source': 'this',
                    'getter_def': None,
                    'mapper_def': None
                })
        self.sources = Utils.filter_non_links(self.sources)

    def source_csv(self, filename: str, **kwargs):
        """Reads the file as CSV and looks for the specified column"""
        column = kwargs.get("column", 0)
        delimiter = kwargs.get("delimiter", ",")
        category_column = kwargs.get("category", -1)
        category_source_column = kwargs.get("category_source", -1)
        getter_def = kwargs.get("getter", -1)
        mapper_def = kwargs.get("mapper", -1)
        #
        with open(filename, "r") as f:
            reader = csv.reader(f, delimiter=delimiter)
            for row in reader:
                if len(row) > max(column, category_column, category_source_column, getter_def, mapper_def):
                    self.sources.append({
                        'url': row[column],
                        'category': row[category_column] if category_column >= 0 else 'unknown',
                        'category_source': row[category_source_column] if category_source_column >= 0 else 'this',
                        'getter_def': row[getter_def] if getter_def >= 0 else None,
                        'mapper_def': row[mapper_def] if mapper_def >= 0 else None
                    })
        self.sources = Utils.filter_non_links(self.sources)

    def source_json(self, filename: str, object_key: str, collection_key=None):
        """
        Reads the file as JSON and looks for the specified keys.
        If collection_key is specified, it will look for the object_key in each object in that collection.
        Else, it will expect the root to be an array of objects and look for the object_key in each object.
        """
        raise NotImplementedError("JSON source loading WIP because of categories")
        # with open(filename, "r") as f:
        #   data = json.load(f)
        #   if collection_key is not None:
        #     if collection_key in data:
        #       for obj in data[collection_key]:
        #         if object_key in obj:
        #           self.sources.append(obj[object_key])
        #   else:
        #     for obj in data:
        #       if object_key in obj:
        #         self.sources.append(obj[object_key])
        # self.sources = U.filter_non_links(self.sources)

    def source_count(self):
        return len(self.sources)

    def load(self):
        """A generator that, for each source, downloads the contents and yields the domains found"""
        for source in self.sources:
            domains: List[Domain]
            try:
                file, info = urllib.request.urlretrieve(source["url"], filename=None)
                content_type = info.get_content_subtype()
                if content_type in self.valid_sources:
                    if content_type == "zip":
                        file = self._unzip_tmp(file)
                    # special edge cases
                    if "urlhaus" in source:
                        domains = self._get_urlhaus(file, source)
                    # other text files
                    else:
                        domains = self._get_txt(file, source)
                    os.remove(file)
                    logger.info("Loaded " + str(len(domains)) + " domains from " + source["url"])
                    yield domains
            except urllib.error.HTTPError as e:
                logger.error(str(e) + " " + source["url"])
            except urllib.error.URLError as e:
                logger.error(str(e) + " " + source["url"])

    def _unzip_tmp(self, file: str):
        """Unzips the file to a temporary directory and returns the path to the unzipped file"""
        with zipfile.ZipFile(file, "r") as zip_ref:
            zip_ref.extractall(self.tmp_dir)
        return self.tmp_dir + "/" + zip_ref.namelist()[0]

    @staticmethod
    def _get_urlhaus(file: str, source: Source):
        domains: List[Domain] = []
        with open(file, 'r', encoding='utf-8', errors='ignore') as csvf:
            reader = csv.reader(csvf)
            URL_COL = 2  # url column in urlhaus csv
            for row in reader:
                if len(row) > URL_COL:
                    domain = re.search(Utils.hostname_regex, row[URL_COL])
                    if domain:
                        domain_name = domain.group(0)  # type: str
                        domains.append({
                            'name': domain_name,
                            'url': row[URL_COL],
                            'source': source["url"],
                            'category': source["category"],
                        })
        return domains

    @staticmethod
    def _get_txt(file: str, source: Source):
        domains: List[Domain] = []
        getter = create_getter(source)
        mapper = create_mapper(source)
        with open(file, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith(Utils.comment_prefixes) or len(line) == 0:
                    continue
                domain = re.search(Utils.hostname_regex, line)
                if domain:
                    domain_name = domain.group(0)  # type: str
                    domains.append({
                        'name': domain_name,
                        'url': line,
                        'source': source["url"],
                        'category': mapper(getter(line)),
                    })
        return domains
