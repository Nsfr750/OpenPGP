"""
SCIM 2.0 Router

Defines all the SCIM 2.0 API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from typing import Optional, Dict, Any, List
from .models import User, Group, ListResponse, SCIMResourceType, ResourceType, ServiceProviderConfig, Schema
from .exceptions import SCIMError, SCIMNotFoundError, SCIMValidationError
from .server import SCIMServer

router = APIRouter(prefix="/scim/v2", tags=["SCIM"])

def get_scim_server(request: Request) -> SCIMServer:
    """Dependency to get the SCIM server instance."""
    return request.app.state.scim_server

@router.get("/ServiceProviderConfig", response_model=Dict[str, Any])
async def get_service_provider_config(
    server: SCIMServer = Depends(get_scim_server)
):
    """Return the service provider's configuration."""
    return server.get_service_provider_config()

@router.get("/ResourceTypes", response_model=List[Dict[str, Any]])
async def get_resource_types(
    server: SCIMServer = Depends(get_scim_server)
):
    """Return the supported resource types."""
    return server.get_resource_types()

@router.get("/ResourceTypes/{resource_type}", response_model=Dict[str, Any])
async def get_resource_type(
    resource_type: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Return a specific resource type."""
    return server.get_resource_type(resource_type)

@router.get("/Schemas", response_model=List[Dict[str, Any]])
async def get_schemas(
    server: SCIMServer = Depends(get_scim_server)
):
    """Return the supported schemas."""
    return server.get_schemas()

@router.get("/Schemas/{schema_urn}", response_model=Dict[str, Any])
async def get_schema(
    schema_urn: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Return a specific schema."""
    return server.get_schema(schema_urn)

# User endpoints
@router.post("/Users", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any])
async def create_user(
    user: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Create a new user."""
    return await server.create_user(user)

@router.get("/Users/{user_id}", response_model=Dict[str, Any])
async def get_user(
    user_id: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Get a user by ID."""
    return await server.get_user(user_id)

@router.get("/Users", response_model=Dict[str, Any])
async def search_users(
    filter: Optional[str] = None,
    start_index: int = 1,
    count: int = 100,
    server: SCIMServer = Depends(get_scim_server)
):
    """Search for users."""
    return await server.search_users(filter=filter, start_index=start_index, count=count)

@router.put("/Users/{user_id}", response_model=Dict[str, Any])
async def replace_user(
    user_id: str,
    user: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Replace a user's data."""
    return await server.replace_user(user_id, user)

@router.patch("/Users/{user_id}", response_model=Dict[str, Any])
async def update_user(
    user_id: str,
    patch: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Update a user with a partial update."""
    return await server.update_user(user_id, patch)

@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Delete a user."""
    await server.delete_user(user_id)
    return None

# Group endpoints (similar structure to user endpoints)
@router.post("/Groups", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any])
async def create_group(
    group: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Create a new group."""
    return await server.create_group(group)

@router.get("/Groups/{group_id}", response_model=Dict[str, Any])
async def get_group(
    group_id: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Get a group by ID."""
    return await server.get_group(group_id)

@router.get("/Groups", response_model=Dict[str, Any])
async def search_groups(
    filter: Optional[str] = None,
    start_index: int = 1,
    count: int = 100,
    server: SCIMServer = Depends(get_scim_server)
):
    """Search for groups."""
    return await server.search_groups(filter=filter, start_index=start_index, count=count)

@router.put("/Groups/{group_id}", response_model=Dict[str, Any])
async def replace_group(
    group_id: str,
    group: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Replace a group's data."""
    return await server.replace_group(group_id, group)

@router.patch("/Groups/{group_id}", response_model=Dict[str, Any])
async def update_group(
    group_id: str,
    patch: Dict[str, Any],
    server: SCIMServer = Depends(get_scim_server)
):
    """Update a group with a partial update."""
    return await server.update_group(group_id, patch)

@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: str,
    server: SCIMServer = Depends(get_scim_server)
):
    """Delete a group."""
    await server.delete_group(group_id)
    return None

# Bulk operations
@router.post("/Bulk", response_model=List[Dict[str, Any]])
async def bulk_operations(
    operations: List[Dict[str, Any]],
    server: SCIMServer = Depends(get_scim_server)
):
    """Process bulk operations."""
    return await server.bulk_operations(operations)

# Export the router
scim_router = router
