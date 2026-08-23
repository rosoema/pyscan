# pyscan/utils/terminal.py


def print_progress(current: int, total: int) -> None:
    """
    Print progress.

    Args:
        current: Current iteration.
        total: Total iterations.
    """
    if total <= 0:
        return

    progress_bar_length = 30

    fraction = current / total
    filled_length = int(progress_bar_length * fraction)

    bar = "█" * filled_length + "░" * (progress_bar_length - filled_length)
    percent = int(fraction * 100)

    print(f"\r[{bar}] {percent:3d}% ({current}/{total})", end="", flush=True)

def clear_line() -> None:
    """Clear the current terminal line."""
    print("\r" + " " * 80 + "\r", end="")