# core/api/endpoints/compliance.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from datetime import datetime
import uuid

from core.compliance import GDPRCompliance, CCPACompliance
from core.compliance.base import DataSubjectRequest, RequestStatus
from core.auth import get_current_user

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

# Initialize compliance handlers
# Note: You'll need to implement or inject the storage backend
gdpr = GDPRCompliance(storage_backend=...)
ccpa = CCPACompliance(storage_backend=...)

@router.post("/gdpr/access")
async def gdpr_access_request(
    user_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Handle GDPR data access request."""
    if current_user["id"] != user_id and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    request = DataSubjectRequest(
        request_id=str(uuid.uuid4()),
        request_type="access",
        requester_id=user_id,
        data={"scope": "all"}  # Could be customized based on request
    )
    
    return await gdpr.process_access_request(request)

@router.post("/gdpr/erasure")
async def gdpr_erasure_request(
    user_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Handle GDPR right to be forgotten request."""
    if current_user["id"] != user_id and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    request = DataSubjectRequest(
        request_id=str(uuid.uuid4()),
        request_type="erasure",
        requester_id=user_id,
        data={"scope": "all"}
    )
    
    return await gdpr.process_erasure_request(request)

@router.post("/ccpa/do-not-sell")
async def ccpa_do_not_sell(
    user_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Handle CCPA "Do Not Sell My Personal Information" request."""
    if current_user["id"] != user_id and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    request = DataSubjectRequest(
        request_id=str(uuid.uuid4()),
        request_type="do_not_sell",
        requester_id=user_id,
        data={}
    )
    
    return await ccpa.process_do_not_sell_request(request)

@router.get("/requests/{request_id}")
async def get_request_status(
    request_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Check the status of a compliance request."""
    # Implementation depends on your storage backend
    request = await storage_backend.get_request(request_id)
    
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if request.requester_id != current_user["id"] and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Not authorized")
    
    return {
        "request_id": request.request_id,
        "status": request.status,
        "created_at": request.created_at,
        "updated_at": request.updated_at
    }