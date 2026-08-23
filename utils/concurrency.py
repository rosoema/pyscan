# pyscan/utils/concurrency.py

import os

from typing import Iterable, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import MAX_WORKERS

from utils.terminal import print_progress


def get_max_workers(
    num_tasks: int,
    requested_workers: int | None = None,
    threads_per_cpu: int = 5,
) -> int:
    """
    Get optimal number of workers.

    Priority:
    1. User-defined (capped)
    2. Adaptive based on CPU
    3. Always bounded by MAX_WORKERS

    Args:
        num_tasks: Total number of tasks.
        requested_workers: User-provided worker count.
        threads_per_cpu: How many threads each core should handle.

    Returns:
        Safe number of workers.
    """
    cpu_count = os.cpu_count() or 1
    auto_thread_count = cpu_count * threads_per_cpu
    workers = max(1, min(auto_thread_count, MAX_WORKERS, num_tasks))

    if requested_workers is not None:
        workers = max(1, min(requested_workers, MAX_WORKERS, num_tasks))

    return workers

def run_tasks_concurrently(
    func: Callable[..., Any],
    items: Iterable,
    max_workers: int | None = None,
    show_progress: bool = False,
) -> list[Any]:
    """
    Run tasks concurrently.

    Each item in `items` is passed to `func`. If an item is a tuple, it is unpacked as arguments.

    Args:
        func: Callable to run on each item.
        items: Iterable of inputs.
        max_workers: Maximum number of threads (default None).
        show_progress: If True, displays a live progress bar.

    Returns:
        List of results (excluding None), according to completion.
    """
    results: list[Any] = []
    items = list(items)
    total = len(items)
    completed = 0

    workers = get_max_workers(total, max_workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(func, *item) if isinstance(item, tuple) else executor.submit(func, item)
            for item in items
        ]

        try:
            for future in as_completed(futures):
                result = future.result()
                completed += 1

                if result is not None:
                    results.append(result)

                if show_progress:
                    print_progress(completed, total)
        except KeyboardInterrupt:
            print("\nCancelling remaining tasks...")
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            raise

    return results