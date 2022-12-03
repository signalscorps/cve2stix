"""
Representation of CVE object stored in stix2_bundles/
"""

from dataclasses import dataclass, field
from typing import List
from stix2 import Vulnerability, Indicator, Relationship, Software, AttackPattern

@dataclass
class CVE:
    vulnerability: Vulnerability
    indicator: "Indicator | None" = None
    # CVE relationship between vulnerability and indicator
    identifies_relationship: "Relationship | None" = None
    enrichment_attack_patterns: List[AttackPattern] = field(default_factory=list)
    enrichment_relationships: List[Relationship] = field(default_factory=list)
    softwares: List[Software] = field(default_factory=list)

