__author__ = "Ondřej Ondryáš"

import time
from functools import wraps
from threading import Semaphore

from logger import logger

_timings = {}
_timing_disabled = True
_sem = Semaphore()


def enable_timing():
    global _timing_disabled
    _timing_disabled = False


def time_exec(func):
    global _timings, _timing_disabled, _sem

    @wraps(func)
    def time_exec_wrapper(*args, **kwargs):
        if _timing_disabled:
            return func(*args, **kwargs)

        start_time = time.perf_counter_ns()
        result = func(*args, **kwargs)
        end_time = time.perf_counter_ns()
        total_time = end_time - start_time

        func_name = func.__qualname__

        _sem.acquire()
        if func_name not in _timings:
            _timings[func_name] = {'time': total_time, 'run_times': 1}
        else:
            _timings[func_name]['time'] += total_time
            _timings[func_name]['run_times'] += 1
        _sem.release()

        return result

    return time_exec_wrapper


def dump():
    global _timings

    for func in _timings.keys():
        run_times = _timings[func]['run_times']
        total_time_s = _timings[func]['time'] / 1000000000
        avg_time = (_timings[func]['time'] / run_times) / 1000000

        logger.info(f"{func}: avg {avg_time:.2f} ms; run total {run_times} times in {total_time_s} s")
