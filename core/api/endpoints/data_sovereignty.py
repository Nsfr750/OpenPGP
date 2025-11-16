# core/api/endpoints/data_sovereignty.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, List, Optional
import json

from core.compliance.data_sovereignty import (
    DataSovereigntyManager, 
    DataJurisdiction,
    DataResidencyRule
)

router = APIRouter(prefix="/api/sovereignty", tags=["data-sovereignty"])

# Initialize data sovereignty manager
sovereignty_manager = DataSovereigntyManager()

@router.get("/jurisdictions", response_model=Dict[str, dict])
async def list_jurisdictions():
    """List all configured jurisdictions and their rules."""
    return {
        juris.value: {
            "allowed_regions": rule.allowed_regions,
            "encryption_required": rule.encryption_required,
            "backup_required": rule.backup_required,
            "retention_period_days": rule.retention_period_days
        }
        for juris, rule in sovereignty_manager.rules.items()
    }

@router.post("/validate-location")
async def validate_data_location(jurisdiction: str, region: str):
    """Validate if data can be stored in the specified region for the given jurisdiction."""
    try:
        juris = DataJurisdiction(jurisdiction)
        is_valid = sovereignty_manager.validate_data_location(juris, region)
        return {
            "jurisdiction": jurisdiction,
            "region": region,
            "is_valid": is_valid,
            "message": f"Data storage in {region} is {'allowed' if is_valid else 'not allowed'} for {jurisdiction}"
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid jurisdiction: {jurisdiction}")

@router.get("/encryption-requirements/{jurisdiction}")
async def get_encryption_requirements(jurisdiction: str):
    """Get encryption requirements for a specific jurisdiction."""
    try:
        juris = DataJurisdiction(jurisdiction)
        return {
            "jurisdiction": jurisdiction,
            "encryption_required": sovereignty_manager.get_encryption_requirements(juris)
        }
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid jurisdiction: {jurisdiction}")

@router.post("/register-jurisdiction/{jurisdiction}")
async def register_jurisdiction(jurisdiction: str):
    """Register an active jurisdiction in the system."""
    try:
        juris = DataJurisdiction(jurisdiction)
        sovereignty_manager.register_jurisdiction(juris)
        return {"status": "success", "message": f"Registered jurisdiction: {jurisdiction}"}
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid jurisdiction: {jurisdiction}")

@router.get("/export-policy")
async def export_policy(file_path: Optional[str] = None):
    """Export the current data sovereignty policy."""
    return json.loads(sovereignty_manager.export_policy(file_path))