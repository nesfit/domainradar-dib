__authors__ = ["Adam Horák", "Ondřej Ondryáš"]

import concurrent.futures
import sys
import threading
import time
from asyncio import Future
from threading import Event

import click
import pymongo

import timing
from config import Config
from datatypes import empty_domain_data, DomainData
from loaders import SourceLoader, DirectLoader, MISPLoader
from logger import logger, logger_thread
from mongo import MongoWrapper
from resolvers import resolve_domain


@click.group()
def cli():
    MongoWrapper.test_connection()


# ----- Domain list loading ----- #
@cli.command('load')
@click.argument('file', type=click.Path(exists=True), required=True)
@click.option('--collection', '-c', type=str, help='The target MongoDB collection for the loaded domains', default='benign')
@click.option('--category', '-t', type=str, help='The category field (if using the -d flag)', default='benign')
@click.option('--direct', '-d', is_flag=True,
              help='Load the file as a list of domain names, instead of interpreting it as a list of sources')
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def load(file, collection, category, direct, yes):
    """Load sources from FILE and store in db"""
    # ask user what type of file it is
    if yes:
        file_type = 'csv'
    else:
        file_type = click.prompt('File type', type=click.Choice(['csv', 'plain']), default='csv')
    # confirm with user before importing
    if not yes:
        if not click.confirm(f"Load domain list(s) from {file} into collection '{collection}'?", default=True):
            return
    else:
        logger.info(f"Importing sources from {file} into collection '{collection}'")
    # load sources from file
    click.echo(f'Loading sources from {file} ({file_type})...')
    if direct:
        loader = DirectLoader(file, category)
    else:
        loader = SourceLoader()
        if file_type == 'csv':
            loader.source_csv(file, column=1, category=5, category_source=6, getter=7, mapper=8)
        elif file_type == 'plain':
            loader.source_plain(file)
        click.echo(f'Found {loader.source_count()} sources')
    # load and store domains in db
    mongo = MongoWrapper(collection)
    mongo.index_by('domain_name')

    try:
        _load_from_loader(loader, mongo)
    except ValueError as e:
        if 'unknown url type' in str(e):
            click.echo('Can\'t download. File is probably a domain list. Try again with --direct or -d.', err=True)
        else:
            click.echo(str(e), err=True)


@cli.command('load-misp')
@click.argument('feed', type=click.Choice(list(Config.MISP_FEEDS.keys())))
@click.option('--collection', '-c', type=str, help='The target MongoDB collection for the loaded domains', default='misp')
def load_misp(feed, collection):
    """Load domains from MISP feed defined in config and selected by FEED name"""
    loader = MISPLoader(feed)
    mongo = MongoWrapper(collection)
    mongo.index_by('domain_name')
    _load_from_loader(loader, mongo)


def _load_from_loader(loader, mongo):
    total_sourced = 0
    total_stored = 0
    total_writes = 0

    for domain_list in loader.load():
        total_sourced += len(domain_list)
        stored, writes = mongo.parallel_store([empty_domain_data(domain)
                                               for domain in domain_list], skip_duplicates=True)
        total_stored += stored
        total_writes += writes
    result = f'Added {total_stored} domains in {total_writes} writes, skipped {total_sourced - total_stored} ' \
             f'duplicates.'
    click.echo(f'Finished: {result}')
    logger.info(result)


# ----- Collection ----- #
@cli.command('resolve', help='Resolve domains stored in db')
@click.option('--type', '-t', 'resolver_type', type=click.Choice(['basic', 'geo',
                                                                  'icmp']), help='Data to resolve',
              default='basic')
@click.option('--collection', '-c', type=str, help='Target collection', default='benign')
@click.option('--retry-evaluated', '-e', is_flag=True,
              help='Retry resolving fields that have failed before', default=False)
@click.option('--force', '-f', is_flag=True,
              help='Force resolving all domains that have already been resolved', default=False)
@click.option('--limit', '-n', type=int, help='Limit number of domains to resolve', default=0)
@click.option('--sequential', '-s', is_flag=True,
              help='Resolve domains sequentially instead of in parallel', default=False)
@click.option('--yes', '-y', is_flag=True, help='Don\'t interact, just start')
def resolve(resolver_type, collection, retry_evaluated, limit, sequential, yes, force):
    """Resolve domains stored in db"""
    mongo = MongoWrapper(collection)
    click.echo(f"Looking for domains without {resolver_type} data in collection '{collection}'.")
    # get domains without data
    unresolved: pymongo.cursor.Cursor[DomainData]

    if resolver_type == 'basic':
        unresolved, count = mongo.get_unresolved(retry_evaluated, force, limit=limit)
    elif resolver_type == 'geo':
        unresolved, count = mongo.get_unresolved_geo(retry_evaluated, force, limit=limit)
    elif resolver_type == 'icmp':
        unresolved, count = mongo.get_unresolved_icmp(retry_evaluated, force, limit=limit)
    else:
        raise RuntimeError('Invalid resolver type')

    if count == 0:
        click.echo('Nothing to resolve.')
        return
    # confirm with user before resolving
    click.echo(f'Found {count} domains.')
    if sequential:
        click.echo('Will resolve sequentially.')

    if resolver_type == 'basic':
        click.echo('Will resolve DNS, TLS, DN RDAP, IP RDAP.')
        if not yes:
            if not click.confirm(f'Begin?', default=True):
                return
    elif resolver_type == 'geo':
        click.echo('Will resolve GEO and ASN data.')
        if not yes:
            if not click.confirm(f'Begin?', default=True):
                return
    elif resolver_type == 'icmp':
        click.echo('Will ping all hosts of found domains.')
        if not yes:
            if not click.confirm(f'Begin?', default=True):
                return

    if Config.ENABLE_TIMING:
        timing.enable_timing()

    # resolve domains
    if sequential:
        _run_sequential_resolving(unresolved, count, mongo, resolver_type, retry_evaluated, force)
    else:
        _run_parallel_resolving(unresolved, count, mongo, resolve_domain, resolver_type, retry_evaluated or force)


def _terminator(executor: concurrent.futures.ThreadPoolExecutor, cancel: Event,
                progress, mongo: MongoWrapper, timeout=None):
    timeout = timeout if timeout else Config.MAXIMUM_TIME_WITHOUT_PROGRESS
    sleep_time = 10
    naps = timeout // sleep_time
    last_pos = progress.pos
    napped = 0
    while True:
        if cancel.is_set():
            break

        time.sleep(sleep_time)
        napped += 1
        if progress.finished:
            break
        elif napped == naps:
            napped = 0
            if progress.pos == last_pos:
                click.echo(f'No progress for {timeout} seconds. Terminating...')
                logger.debug(f'No progress for {timeout} seconds. Run terminated.')
                executor.shutdown(wait=False, cancel_futures=True)
                mongo.cleanup()
                click.echo('DB buffer flushed safely.')
                sys.exit(1)
            else:
                last_pos = progress.pos


def _run_sequential_resolving(unresolved, count, mongo, resolver_type, retry_evaluated, force):
    cancel_event = Event()
    with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
        i = 0
        for domain in unresolved:
            i += 1
            resolve_domain(cancel_event, domain, i, mongo, resolver_type, retry_evaluated or force)
            resolving.update(1)
    timing.dump()


def _run_parallel_resolving(unresolved, count, mongo, exec_func, *args):
    cancel_event = Event()

    with click.progressbar(length=count, show_pos=True, show_percent=True) as resolving:
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            terminator_thread = threading.Thread(target=_terminator, args=(executor, cancel_event, resolving, mongo))
            terminator_thread.start()

            futures: list[Future] = []
            batch = 1
            total_batches = count // Config.PROCESSING_BATCH_SIZE
            dom_num = 0
            total_done = 0

            for domain in unresolved:
                dom_num += 1
                futures.append(executor.submit(exec_func, cancel_event, domain, dom_num, mongo, *args))

                batch_size = min(Config.PROCESSING_BATCH_SIZE, count - total_done)
                if len(futures) == batch_size:
                    completed_count = 0
                    logger.info(f"Batch {batch}/{total_batches} starting")
                    # noinspection PyBroadException
                    try:
                        for completed in concurrent.futures.as_completed(futures, timeout=Config.TIMEOUT_PER_BATCH):
                            # check for errors
                            try:
                                completed.result()
                            except KeyboardInterrupt:
                                raise
                            except BaseException as err:
                                logger_thread.exception(f'Exception in resolving thread in batch #{batch}',
                                                        exc_info=err)
                            # update progress bar
                            resolving.update(1)
                            completed_count += 1
                            total_done += 1
                    except KeyboardInterrupt:
                        logger_thread.warning(f"Interrupted manually")
                        executor.shutdown(wait=False, cancel_futures=True)
                        cancel_event.set()
                        mongo.flush()
                        break
                    except BaseException:  # for some reason, TimeoutError doesn't get caught here
                        logger_thread.error(f"Batch #{batch} didn't complete in {Config.TIMEOUT_PER_BATCH} s")
                        resolving.update(Config.PROCESSING_BATCH_SIZE - completed_count)
                        mongo.flush()

                    futures.clear()
                    batch += 1

            timing.dump()
            click.echo(f'\nWaiting for terminator... (max 10 seconds)')
            terminator_thread.join(timeout=10)


if __name__ == '__main__':
    cli()
