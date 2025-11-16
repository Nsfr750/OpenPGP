# core/compliance/base.py
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

class RequestStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class DataSubjectRequest:
    request_id: str
    request_type: str  # e.g., "access", "erasure", "portability"
    requester_id: str
    data: Dict[str, Any]
    status: RequestStatus = RequestStatus.PENDING
    created_at: datetime = None
    updated_at: datetime = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = self.created_at

@dataclass
class DataProcessingActivity:
    activity_id: str
    name: str
    description: str
    legal_basis: str
    data_categories: List[str]
    retention_period: str
    created_at: datetime = None
    updated_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = self.created_at