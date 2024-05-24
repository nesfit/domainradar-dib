__author__ = "Adam Horák"

import re
from typing import Callable, List

from datatypes import Source


class LoaderUtils:
    comment_prefixes = ("#", ";", "//")
    ip_regex = r"^((?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::)))))|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    hostname_regex = r"(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]"

    @staticmethod
    def filter_non_links(sources: List[Source]):
        """Filters out any sources that don't contain a match for the hostname regex"""
        return [source for source in sources if re.search(LoaderUtils.hostname_regex, source["url"])]


def create_getter(source: Source) -> Callable[[str], str]:
    """Creates a category getter function for the specified source list"""
    # if the category is specified in the source, return a function that always returns it
    if source["category_source"] == "this":
        return lambda _: source["category"]
    # if not and there's no getter definition, return a function that always returns 'unknown'
    elif source["getter_def"] is None or source["getter_def"] == "":
        return lambda _: 'unknown'
    # otherwise, return a function that returns the category based on the getter definition
    else:
        definition = source["getter_def"]
        # if the category is specified in a CSV column, the definition is the delimiter character and column number
        if source["category_source"] == "csv":
            # example for delimiter semicolon and column index 21: ";21"
            delimiter, column = definition[0], int(definition[1:])

            def csv_getter(line: str):
                try:
                    return line.split(delimiter)[column]
                except IndexError:
                    return 'unknown'

            return csv_getter
        # if the category is specified somewhere in the line, the definition is a regex to find it
        elif source["category_source"] == "txt":
            def txt_getter(line: str):
                cat = re.search(definition, line)
                if cat and len(cat.groups()) > 0:
                    return cat.group(1)
                else:
                    return 'unknown'

            return txt_getter
        # if the category source is something else, return a function that always returns 'unknown'
        else:
            return lambda _: 'unknown'


def _rule_parser(rule: str):
    """Parses a rule into a tuple of (regex, category)"""
    parts = rule.split("=")
    if len(parts) == 2:
        return parts[0], parts[1]
    else:
        return parts[0], 'unknown'


def create_mapper(source: Source) -> Callable[[str], str]:
    """Creates a mapper function for the specified source"""
    if source["mapper_def"] is None or source["mapper_def"] == "":
        return lambda x: x
    else:
        definition = source["mapper_def"]
        raw_rules = definition.split(";")
        rules = list(map(_rule_parser, raw_rules))

        def mapper(line: str):
            if line == 'unknown':
                return 'unknown'
            for pattern, category in rules:
                if re.search(pattern, line, re.IGNORECASE):
                    return category
            return 'unknown'

        return mapper
