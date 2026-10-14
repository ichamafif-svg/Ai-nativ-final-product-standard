"""U — the agent: autonomous, never sovereign (ARCHITECTURE.md §11).

One loop reads the game, producers write candidate commits in the agent's own store, and the agent plays the moves the
rules allow. It reaches K/T only through the admission service; it holds no credential but its own signing key and
one capability, and never closes a debt.
"""
from .agent import Agent, AgentError
from .build import Builder
from .context import gap_dossiers
from .loop import Loop
from .moves import judge, moves, queue
from .patrol import patrol_context
from .projection import Route, project
from .repair import Repairer
from .work import WorkEngine, WorkError

__all__ = ["Agent", "AgentError", "Builder", "Loop", "Repairer", "Route", "project", "gap_dossiers",
           "patrol_context", "judge", "moves", "queue", "WorkEngine", "WorkError"]
