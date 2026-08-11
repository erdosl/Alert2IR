"""Persistence adapters for Alert2IR application contracts."""

from alert2ir.persistence.memory import InMemoryProcessingRepository
from alert2ir.persistence.postgres import PostgresProcessingRepository

__all__ = ["InMemoryProcessingRepository", "PostgresProcessingRepository"]
