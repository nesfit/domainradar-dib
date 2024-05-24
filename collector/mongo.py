"""Mongo wrapper that handles dataset storage"""
__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

import atexit
import concurrent.futures
import sys
from math import ceil
from typing import List, Tuple

import click
import pymongo
import pymongo.errors
from pymongo.cursor import Cursor

from config import Config
from datatypes import DomainData
from logger import logger


def chunks(source_list: List, n: int):
    """Yield successive equal about-n-sized chunks from source_list."""
    chunk_count = ceil(len(source_list) / n)
    if chunk_count == 0:
        yield source_list
    else:
        chunk_size = ceil(len(source_list) / chunk_count)
        for i in range(0, len(source_list), chunk_size):
            yield source_list[i:i + chunk_size]


class MongoWrapper:
    batch_queue = []

    @staticmethod
    def test_connection():
        try:
            client = pymongo.MongoClient(Config.MONGO_URI)
            client.server_info()
        except Exception as e:
            logger.error("DB: Connection to MongoDB failed, check your connection settings", exc_info=e)
            print("Connection to MongoDB failed, check your connection settings. Exiting...")
            sys.exit(1)

    def __init__(self, collection: str, write_batch_size: int = Config.MONGO_WRITE_BATCH_SIZE):
        self._client = pymongo.MongoClient(Config.MONGO_URI)
        self._db = self._client[Config.MONGO_DB]
        self._collection = self._db[collection]
        self._write_batch_size = write_batch_size
        self._closed = False
        atexit.register(self.cleanup)

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        if self._closed:
            return

        if self._write_batch_size > len(self.batch_queue) > 0:
            logger.debug("DB: Flushed remaining " + str(len(self.batch_queue)) + " items before exit")
        self._flush('domain_name')
        self._client.close()
        self._closed = True

    def _insert(self, data: List):
        return self._collection.insert_many(data)

    def _upsert(self, data: List, key: str, skip_duplicates: bool = False):
        updates = [pymongo.UpdateOne({key: d[key]},
                                     {'$setOnInsert' if skip_duplicates else '$set': d},
                                     upsert=True) for d in data]
        return self._collection.bulk_write(updates, ordered=False)

    def _upsert_one(self, data: dict, key: str):
        return self._collection.update_one({key: data[key]}, {'$set': data}, upsert=True)

    def _flush(self, key: str, skip_duplicates: bool = False):
        if self.batch_queue:
            self._upsert(self.batch_queue, key, skip_duplicates)
            self.batch_queue.clear()

    def index_by(self, key: str):
        try:
            self._collection.create_index(key, name=f'{key}_index', unique=True)
        except pymongo.errors.OperationFailure:
            pass

    def update_one(self, filter: dict, data: dict):
        return self._collection.update_one(filter, data)

    def flush(self, skip_duplicates: bool = False):
        self._flush(key='domain_name', skip_duplicates=skip_duplicates)

    # storing

    def store(self, data: DomainData, skip_duplicates: bool = False):
        # add to batch queue
        self.batch_queue.append(data)
        # flush if batch queue is full
        if len(self.batch_queue) >= self._write_batch_size:
            logger.debug("DB: Batch queue full, flushing " + str(len(self.batch_queue)) + " items")
            self._flush(key='domain_name', skip_duplicates=skip_duplicates)

    def bulk_store(self, data: List[DomainData]):
        """Bulk store data, no batch queue, no auto collection switching (make sure to switch_collection() first
        if you need to)"""
        self._upsert(data, key='domain_name')

    def parallel_store(self, data: List[DomainData], skip_duplicates: bool = False):
        """Store data in parallel, no batch queue, no auto collection switching (make sure to switch_collection() first
        if you need to)"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            click.echo(f'Preparing {len(data)} items...')
            futures = [executor.submit(self._upsert, chunk, 'domain_name', skip_duplicates)
                       for chunk in chunks(data, Config.PROCESSING_BATCH_SIZE)]
            stored = 0
            with click.progressbar(length=len(futures), show_pos=True, show_percent=True, label="Writes") as loading:
                for future in concurrent.futures.as_completed(futures):
                    loading.update(1)
                    stored += future.result().upserted_count
            result = f'Stored {stored} of {len(data)} items in {len(futures)} writes'
            logger.info(result)
            click.echo(result)
        return stored, len(futures)

    # retrieving
    def _find_query(self, query, limit: int = 0) -> Tuple[Cursor[DomainData], int]:
        db_count = self._collection.count_documents(query)
        count = db_count if limit == 0 else min(limit, db_count)
        return self._collection.find(query, limit=limit, batch_size=Config.PROCESSING_BATCH_SIZE), count

    def get_unresolved(self, retry_evaluated=False, force=False, limit: int = 0):
        if force:
            query = {}
        elif retry_evaluated:
            query = {'$or': [{'rdap': None},
                             {'ip_data': None},
                             {'ip_data': {'$elemMatch': {'rdap': None}}},
                             {'ip_data': {'$elemMatch': {'asn': None}}},
                             {'tls': None},
                             {'dns': None}]}
        else:
            query = {'$or': [{'remarks.rdap_evaluated_on': None},
                             {'ip_data': {'$elemMatch': {'remarks.rdap_evaluated_on': None}}},
                             {'ip_data': {'$elemMatch': {'remarks.asn_evaluated_on': None}}},
                             {'remarks.tls_evaluated_on': None},
                             {'remarks.dns_evaluated_on': None}]}
        return self._find_query(query, limit)

    def get_unresolved_geo(self, retry_evaluated=False, force=False, limit: int = 0):
        if force:
            query = {}
        elif retry_evaluated:
            query = {'$or': [{'ip_data': {'$elemMatch': {'geo': None}}},
                             {'ip_data': {'$elemMatch': {'asn': None}}}]}
        else:
            query = {'$or': [{'ip_data': {'$elemMatch': {'remarks.geo_evaluated_on': None}}},
                             {'ip_data': {'$elemMatch': {'remarks.asn_evaluated_on': None}}}]}
        return self._find_query(query, limit)

    def get_unresolved_icmp(self, retry_evaluated=False, force=False, limit: int = 0):
        if force:
            query = {}
        elif retry_evaluated:
            query = {'ip_data': {'$exists': True}}
        else:
            query = {'ip_data': {'$elemMatch': {'remarks.icmp_evaluated_on': None}}}
        return self._find_query(query, limit)
