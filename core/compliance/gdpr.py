# core/compliance/gdpr.py
from datetime import timedelta
from typing import Dict, List, Optional
from .base import DataSubjectRequest, RequestStatus, DataProcessingActivity

class GDPRCompliance:
    """Handles GDPR compliance requirements."""
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
        self.data_retention_period = timedelta(days=730)  # 2 years by default
        
    async def process_access_request(self, request: DataSubjectRequest) -> Dict:
        """Process a data access request under GDPR."""
        request.status = RequestStatus.IN_PROGRESS
        request.updated_at = datetime.utcnow()
        
        try:
            # Retrieve all user data
            user_data = await self.storage.retrieve_user_data(request.requester_id)
            
            # Log the access
            await self._log_data_access(
                request.requester_id,
                "data_access",
                f"Data access request {request.request_id} processed"
            )
            
            request.status = RequestStatus.COMPLETED
            return {
                "status": "success",
                "request_id": request.request_id,
                "data": user_data
            }
        except Exception as e:
            request.status = RequestStatus.FAILED
            raise
    
    async def process_erasure_request(self, request: DataSubjectRequest) -> Dict:
        """Process a right to be forgotten request under GDPR."""
        request.status = RequestStatus.IN_PROGRESS
        request.updated_at = datetime.utcnow()
        
        try:
            # Anonymize or delete user data
            await self.storage.anonymize_user_data(request.requester_id)
            
            # Log the erasure
            await self._log_data_access(
                request.requester_id,
                "erasure",
                f"Data erasure request {request.request_id} processed"
            )
            
            request.status = RequestStatus.COMPLETED
            return {
                "status": "success",
                "request_id": request.request_id,
                "message": "Data has been anonymized"
            }
        except Exception as e:
            request.status = RequestStatus.FAILED
            raise
    
    async def register_processing_activity(self, activity: DataProcessingActivity) -> bool:
        """Register a data processing activity as required by GDPR Article 30."""
        return await self.storage.store_processing_activity(activity)
    
    async def _log_data_access(self, user_id: str, action: str, details: str):
        """Log data access for compliance purposes."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "details": details,
            "ip_address": None,  # Should be populated from request context
            "user_agent": None   # Should be populated from request context
        }
        await self.storage.store_audit_log(log_entry)