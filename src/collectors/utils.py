import time
import requests
from functools import wraps
from typing import Callable, Any


def retry_on_failure(max_retries: int = 3, delay: int = 5):
    """
    Decorator to retry a function on failure with exponential backoff.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None

            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (requests.RequestException, Exception) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)
                        print(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        print(f"All {max_retries} attempts failed. Last error: {e}")

            return 0

        return wrapper
    return decorator
