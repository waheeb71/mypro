"""
Time Schedules
Time-based policy enforcement.
"""

from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import List, Optional

@dataclass
class Schedule:
    name: str
    days: List[str]  # Mon, Tue, Wed...
    start_time: time
    end_time: time
    timezone: str = "UTC"

    def is_active(self, current_time: datetime) -> bool:
        # Check Time
        now_time = current_time.time()
        width_day = current_time.strftime("%a")

        if self.start_time <= self.end_time:
            # Same-day window
            if width_day not in self.days:
                return False
            return self.start_time <= now_time <= self.end_time

        # Crosses midnight: late night of listed day OR early hours of next day
        if now_time >= self.start_time:
            return width_day in self.days

        # After midnight: compare against previous day
        prev_day = (current_time - timedelta(days=1)).strftime("%a")
        return prev_day in self.days and now_time <= self.end_time
