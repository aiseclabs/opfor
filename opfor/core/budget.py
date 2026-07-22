"""The budget: a runaway cap on how much work one run may do.

A count of steps, one charged per task the engine runs. When the budget is spent
the engine stops and reports the run suspended rather than clean, so a resume can
continue from the checkpoint. The cap is a safety rail against a planner that never
stops proposing work, not a scheduler.
"""

from __future__ import annotations


class Budget:
    def __init__(self, max_steps: int) -> None:
        self.max_steps = max_steps
        self.steps = 0

    def has_steps(self) -> bool:
        return self.steps < self.max_steps

    def charge(self, n: int = 1) -> None:
        self.steps += n
