# core/compliance/data_sovereignty.py
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum
import logging
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class DataJurisdiction(str, Enum):
    """Supported data jurisdictions with their requirements."""
    EU_GDPR = "EU"          # European Union - GDPR
    US_CCPA = "US_CA"       # USA - California (CCPA)
    US_HIPAA = "US_HIPAA"   # USA - Healthcare (HIPAA)
    AU_APP = "AU"           # Australia - APP
    JP_APPI = "JP"          # Japan - APPI
    DEFAULT = "GLOBAL"      # Default global jurisdiction

@dataclass
class DataResidencyRule:
    """Defines where data for a specific jurisdiction must be stored."""
    jurisdiction: DataJurisdiction
    allowed_regions: List[str]  # e.g., ["europe-west3", "europe-west4"]
    encryption_required: bool = True
    backup_required: bool = True
    retention_period_days: int = 730  # 2 years default

class DataSovereigntyManager:
    """Manages data sovereignty controls and ensures compliance with data residency requirements."""
    
    def __init__(self, rules: Dict[DataJurisdiction, DataResidencyRule] = None):
        self.rules = rules or self._get_default_rules()
        self.active_jurisdictions: Set[DataJurisdiction] = set()
        
    def _get_default_rules(self) -> Dict[DataJurisdiction, DataResidencyRule]:
        """Get default data residency rules."""
        return {
            DataJurisdiction.EU_GDPR: DataResidencyRule(
                jurisdiction=DataJurisdiction.EU_GDPR,
                allowed_regions=["europe-west1", "europe-west3"],
                encryption_required=True,
                backup_required=True,
                retention_period_days=1095  # 3 years for GDPR
            ),
            DataJurisdiction.US_CCPA: DataResidencyRule(
                jurisdiction=DataJurisdiction.US_CCPA,
                allowed_regions=["us-central1", "us-west1"],
                encryption_required=True,
                backup_required=True
            ),
            DataJurisdiction.DEFAULT: DataResidencyRule(
                jurisdiction=DataJurisdiction.DEFAULT,
                allowed_regions=["global"],
                encryption_required=True,
                backup_required=False
            )
        }
    
    def get_jurisdiction_rule(self, jurisdiction: DataJurisdiction) -> DataResidencyRule:
        """Get the rule for a specific jurisdiction."""
        return self.rules.get(jurisdiction, self.rules[DataJurisdiction.DEFAULT])
    
    def validate_data_location(self, jurisdiction: DataJurisdiction, region: str) -> bool:
        """Validate if data can be stored in the specified region for the given jurisdiction."""
        rule = self.get_jurisdiction_rule(jurisdiction)
        return region in rule.allowed_regions
    
    def get_encryption_requirements(self, jurisdiction: DataJurisdiction) -> bool:
        """Get encryption requirements for a jurisdiction."""
        rule = self.get_jurisdiction_rule(jurisdiction)
        return rule.encryption_required
    
    def get_retention_period(self, jurisdiction: DataJurisdiction) -> int:
        """Get data retention period in days for a jurisdiction."""
        rule = self.get_jurisdiction_rule(jurisdiction)
        return rule.retention_period_days
    
    def register_jurisdiction(self, jurisdiction: DataJurisdiction) -> None:
        """Register an active jurisdiction in the system."""
        self.active_jurisdictions.add(jurisdiction)
        logger.info(f"Registered jurisdiction: {jurisdiction.value}")
    
    def get_active_jurisdictions(self) -> Set[DataJurisdiction]:
        """Get all active jurisdictions in the system."""
        return self.active_jurisdictions
    
    def export_policy(self, file_path: Optional[str] = None) -> str:
        """Export current data sovereignty policy to a file or return as JSON string."""
        policy = {
            "version": "1.0",
            "last_updated": datetime.utcnow().isoformat(),
            "jurisdictions": {
                juris.value: {
                    "allowed_regions": rule.allowed_regions,
                    "encryption_required": rule.encryption_required,
                    "backup_required": rule.backup_required,
                    "retention_period_days": rule.retention_period_days
                }
                for juris, rule in self.rules.items()
            }
        }
        
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(policy, f, indent=2)
            return f"Policy exported to {file_path}"
        
        return json.dumps(policy, indent=2)