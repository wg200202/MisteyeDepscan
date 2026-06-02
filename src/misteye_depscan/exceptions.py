"""Shared CLI / scanner exceptions."""


class ScanInterrupted(Exception):
    """Scan was cancelled by the user (Ctrl+C)."""

    def __init__(self, completed: int = 0, total: int = 0) -> None:
        self.completed = completed
        self.total = total
        super().__init__()
