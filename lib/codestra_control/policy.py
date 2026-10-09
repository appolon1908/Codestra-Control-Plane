"""Resolve promotion edges from an independently loaded product registry."""

from dataclasses import dataclass
import re


class PolicyError(ValueError):
    """The registered mapping or requested promotion path is invalid."""


@dataclass(frozen=True)
class ScopeEdge:
    source_level: str
    source_ref: str
    target_level: str
    target_ref: str


@dataclass(frozen=True)
class ProductMapping:
    repository: str
    product: str
    development_ref: str
    testing_ref: str
    staging_ref: str
    production_ref: str
    release_ref: str
    scope_edges: tuple[ScopeEdge, ...] = ()


def valid_ref(ref: str) -> bool:
    """Conservative short branch names, not refspecs, options or full refs."""
    if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", ref):
        return False
    if ref.startswith("refs/") or ".." in ref or ref.endswith(("/", ".")):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock")
               for part in ref.split("/"))


def registered_edges(mapping: ProductMapping) -> tuple[ScopeEdge, ...]:
    if type(mapping) is not ProductMapping:
        raise PolicyError("INVALID_PRODUCT_MAPPING")
    if (not isinstance(mapping.repository, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", mapping.repository)
            or not isinstance(mapping.product, str) or not mapping.product.strip()):
        raise PolicyError("INVALID_REGISTRY_IDENTITY")
    refs = (mapping.development_ref, mapping.testing_ref, mapping.staging_ref,
            mapping.production_ref, mapping.release_ref)
    if not all(valid_ref(ref) for ref in refs) or len(set(refs)) != len(refs):
        raise PolicyError("INVALID_ENVIRONMENT_REFS")
    levels = ("development", "testing", "staging", "production", "main")
    edges = tuple(ScopeEdge(levels[i], refs[i], levels[i + 1], refs[i + 1]) for i in range(4))
    if type(mapping.scope_edges) is not tuple:
        raise PolicyError("INVALID_SCOPE_REGISTRY")
    source_refs = set(refs)
    for edge in mapping.scope_edges:
        if (type(edge) is not ScopeEdge or not valid_ref(edge.source_ref)
                or not valid_ref(edge.target_ref)
                or (edge.source_level, edge.target_level) not in {
                    ("subsection", "section"), ("section", "development")}):
            raise PolicyError("INVALID_SCOPE_EDGE")
        if edge.source_ref in source_refs:
            raise PolicyError("AMBIGUOUS_SCOPE_REF")
        if edge.source_level == "section" and edge.target_ref != mapping.development_ref:
            raise PolicyError("INVALID_SECTION_PARENT")
        if edge.source_level == "subsection" and edge.target_ref in refs:
            raise PolicyError("INVALID_SUBSECTION_PARENT")
        source_refs.add(edge.source_ref)
    # Every subsection's parent must itself have a registered section edge.
    sections = {edge.source_ref for edge in mapping.scope_edges if edge.source_level == "section"}
    if any(edge.source_level == "subsection" and edge.target_ref not in sections for edge in mapping.scope_edges):
        raise PolicyError("UNREGISTERED_SECTION_PARENT")
    return edges + mapping.scope_edges


def resolve_edge(mapping: ProductMapping, source_ref: str, target_ref: str) -> tuple[str, str]:
    for edge in registered_edges(mapping):
        if (edge.source_ref, edge.target_ref) == (source_ref, target_ref):
            return edge.source_level, edge.target_level
    raise PolicyError("ILLEGAL_PROMOTION_EDGE")
