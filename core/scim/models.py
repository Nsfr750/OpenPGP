"""
SCIM 2.0 Data Models

Defines the core data models for SCIM 2.0 resources including Users, Groups,
and other SCIM entities.
"""
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl, EmailStr
from enum import Enum
import uuid

class SCIMResourceType(str, Enum):
    """SCIM resource types."""
    USER = "User"
    GROUP = "Group"
    RESOURCE_TYPE = "ResourceType"
    SCHEMA = "Schema"
    SERVICE_PROVIDER_CONFIG = "ServiceProviderConfig"

class Meta(BaseModel):
    """SCIM meta attributes."""
    resource_type: Optional[SCIMResourceType] = Field(alias="resourceType")
    created: Optional[datetime]
    last_modified: Optional[datetime] = Field(alias="lastModified")
    location: Optional[HttpUrl]
    version: Optional[str]

    class Config:
        allow_population_by_field_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        }

class Name(BaseModel):
    """SCIM name component."""
    formatted: Optional[str]
    family_name: Optional[str] = Field(alias="familyName")
    given_name: Optional[str] = Field(alias="givenName")
    middle_name: Optional[str] = Field(alias="middleName")
    honorific_prefix: Optional[str] = Field(alias="honorificPrefix")
    honorific_suffix: Optional[str] = Field(alias="honorificSuffix")

    class Config:
        allow_population_by_field_name = True

class Email(BaseModel):
    """SCIM email component."""
    value: EmailStr
    display: Optional[str]
    type: Optional[str] = "work"
    primary: bool = False

class PhoneNumber(BaseModel):
    """SCIM phone number component."""
    value: str
    display: Optional[str]
    type: str = "work"
    primary: bool = False

class Address(BaseModel):
    """SCIM address component."""
    formatted: Optional[str]
    street_address: Optional[str] = Field(alias="streetAddress")
    locality: Optional[str]
    region: Optional[str]
    postal_code: Optional[str] = Field(alias="postalCode")
    country: Optional[str]
    type: str = "work"
    primary: bool = False

    class Config:
        allow_population_by_field_name = True

class BaseResource(BaseModel):
    """Base SCIM resource with common attributes."""
    schemas: List[str]
    id: Optional[str] = None
    external_id: Optional[str] = Field(None, alias="externalId")
    meta: Optional[Meta] = None

    class Config:
        allow_population_by_field_name = True

    def to_scim(self) -> Dict[str, Any]:
        """Convert to SCIM JSON representation."""
        return self.dict(exclude_none=True, by_alias=True)

class User(BaseResource):
    """SCIM 2.0 User resource."""
    user_name: str = Field(..., alias="userName")
    name: Optional[Name]
    display_name: Optional[str] = Field(None, alias="displayName")
    nick_name: Optional[str] = Field(None, alias="nickName")
    profile_url: Optional[HttpUrl] = Field(None, alias="profileUrl")
    title: Optional[str]
    user_type: Optional[str] = Field(None, alias="userType")
    preferred_language: Optional[str] = Field(None, alias="preferredLanguage")
    locale: Optional[str]
    timezone: Optional[str]
    active: bool = True
    password: Optional[str] = None
    emails: Optional[List[Email]] = None
    phone_numbers: Optional[List[PhoneNumber]] = Field(None, alias="phoneNumbers")
    addresses: Optional[List[Address]] = None
    groups: Optional[List[Dict[str, str]]] = None
    entitlements: Optional[List[Dict[str, str]]] = None
    roles: Optional[List[Dict[str, str]]] = None
    x509_certificates: Optional[List[Dict[str, str]]] = Field(None, alias="x509Certificates")

    def __init__(self, **data):
        if 'schemas' not in data:
            data['schemas'] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
        super().__init__(**data)

class Group(BaseResource):
    """SCIM 2.0 Group resource."""
    display_name: str = Field(..., alias="displayName")
    members: Optional[List[Dict[str, str]]] = None

    def __init__(self, **data):
        if 'schemas' not in data:
            data['schemas'] = ["urn:ietf:params:scim:schemas:core:2.0:Group"]
        super().__init__(**data)

class ResourceType(BaseModel):
    """SCIM 2.0 Resource Type."""
    schemas: List[str] = ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"]
    id: str
    name: str
    endpoint: str
    description: Optional[str] = None
    schema: str
    schema_extensions: Optional[List[Dict[str, str]]] = Field(None, alias="schemaExtensions")

class Schema(BaseModel):
    """SCIM 2.0 Schema."""
    schemas: List[str] = ["urn:ietf:params:scim:schemas:core:2.0:Schema"]
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    attributes: List[Dict[str, Any]]

class ListResponse(BaseModel):
    """SCIM 2.0 List Response."""
    schemas: List[str] = ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    total_results: int = Field(..., alias="totalResults")
    items_per_page: Optional[int] = Field(None, alias="itemsPerPage")
    start_index: int = Field(1, alias="startIndex")
    resources: List[Dict[str, Any]] = Field(default_factory=list, alias="Resources")

    class Config:
        allow_population_by_field_name = True
