# core/storage/compliance_storage.py
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import os
from pathlib import Path

from core.compliance.base import DataSubjectRequest, DataProcessingActivity

class ComplianceStorage:
    """Storage backend for compliance-related data."""
    
    def __init__(self, storage_path: str = "data/compliance"):
        """
        Initialize the compliance storage.
        
        Args:
            storage_path: Base directory for storing compliance data
        """
        self.storage_path = Path(storage_path)
        self.ensure_directories_exist()
        
    def ensure_directories_exist(self):
        """Ensure all required directories exist."""
        (self.storage_path / "requests").mkdir(parents=True, exist_ok=True)
        (self.storage_path / "activities").mkdir(parents=True, exist_ok=True)
        (self.storage_path / "audit_logs").mkdir(parents=True, exist_ok=True)
    
    # Request management
    async def store_request(self, request: DataSubjectRequest) -> bool:
        """Store a data subject request."""
        file_path = self.storage_path / "requests" / f"{request.request_id}.json"
        with open(file_path, 'w') as f:
            json.dump({
                "request_id": request.request_id,
                "request_type": request.request_type,
                "requester_id": request.requester_id,
                "status": request.status,
                "data": request.data,
                "created_at": request.created_at.isoformat(),
                "updated_at": request.updated_at.isoformat(),
                "metadata": request.metadata or {}
            }, f, indent=2)
        return True
    
    async def get_request(self, request_id: str) -> Optional[DataSubjectRequest]:
        """Retrieve a data subject request by ID."""
        file_path = self.storage_path / "requests" / f"{request_id}.json"
        if not file_path.exists():
            return None
            
        with open(file_path, 'r') as f:
            data = json.load(f)
            return DataSubjectRequest(
                request_id=data["request_id"],
                request_type=data["request_type"],
                requester_id=data["requester_id"],
                data=data["data"],
                status=data["status"],
                created_at=datetime.fromisoformat(data["created_at"]),
                updated_at=datetime.fromisoformat(data["updated_at"]),
                metadata=data.get("metadata")
            )
    
    # Data processing activities
    async def store_processing_activity(self, activity: DataProcessingActivity) -> bool:
        """Store a data processing activity record."""
        file_path = self.storage_path / "activities" / f"{activity.activity_id}.json"
        with open(file_path, 'w') as f:
            json.dump({
                "activity_id": activity.activity_id,
                "name": activity.name,
                "description": activity.description,
                "legal_basis": activity.legal_basis,
                "data_categories": activity.data_categories,
                "retention_period": activity.retention_period,
                "created_at": activity.created_at.isoformat(),
                "updated_at": activity.updated_at.isoformat()
            }, f, indent=2)
        return True
    
    # Audit logging
    async def store_audit_log(self, log_entry: Dict[str, Any]) -> bool:
        """Store an audit log entry."""
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        log_file = self.storage_path / "audit_logs" / f"audit_{timestamp}.log"
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
        return True
    
    # User data operations
    async def retrieve_user_data(self, user_id: str) -> Dict[str, Any]:
        """Retrieve all data for a specific user (to be implemented based on your data model)."""
        # This is a placeholder - implement based on your actual data storage
        return {
            "user_id": user_id,
            "data_retrieved_at": datetime.utcnow().isoformat()
        }
    
    async def anonymize_user_data(self, user_id: str) -> bool:
        """Anonymize user data (to be implemented based on your data model)."""
        # This is a placeholder - implement based on your actual data storage
        return True
    
    async def update_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Update user preferences (to be implemented based on your data model)."""
        # This is a placeholder - implement based on your actual data storage
        return True