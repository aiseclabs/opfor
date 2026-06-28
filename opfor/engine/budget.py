"""Budget, the runaway guard.

Bounds how much work a run may do. A best-practice control loop always caps its
own iteration so a planner bug or a hostile target cannot spin it forever.
"""

from __future__ import annotations


class Budget:
    def __init__(self, max_steps: int) -> None:
        self.max_steps = max_steps
        self.steps = 0

    def ok(self) -> bool:
        return self.steps < self.max_steps

    def charge(self, n: int = 1) -> None:
        self.steps += n

    def remaining(self) -> int:
        return max(0, self.max_steps - self.steps)
