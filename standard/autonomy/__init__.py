"""U — autonomous, never sovereign (ARCHITECTURE.md §11).

Projection of debts onto work, the Work Engine, the agent and the RUN cycle. It reaches K/T only through the admission
service; it holds no credential but its own signing key and never closes a debt.
"""
from .agent import Agent, AgentError
from .cycle import Cycle
from .drift_map import gap_dossiers
from .law_surface import law_surface_map
from .patrol import patrol_context
from .projection import Route, project
from .work import WorkEngine, WorkError

__all__ = ["Agent", "AgentError", "Cycle", "Route", "project", "gap_dossiers", "patrol_context", "law_surface_map",
           "WorkEngine", "WorkError"]
