import time
from dataclasses import dataclass


@dataclass
class RateCounter:
    last_tick: float = 0.0
    last_count: int = 0

    def __post_init__(self) -> None:
        if self.last_tick == 0.0:
            self.last_tick = time.perf_counter()

    def rate(self, total_count: int) -> float:
        now = time.perf_counter()
        delta_t = max(now - self.last_tick, 1e-9)
        delta_c = total_count - self.last_count
        self.last_tick = now
        self.last_count = total_count
        return delta_c / delta_t
