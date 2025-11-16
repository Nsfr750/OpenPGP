# core/api/endpoints/privacy.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any
import numpy as np
from core.crypto import PrivacyPreservingComputations
from core.crypto.homomorphic import HomomorphicEncryption

router = APIRouter(prefix="/api/privacy", tags=["privacy"])

# Initialize the privacy-preserving computations
ppc = PrivacyPreservingComputations()

@router.post("/encrypt")
async def encrypt_data(data: List[float]):
    """Encrypt a list of numbers."""
    try:
        encrypted = ppc.he.encrypt(data)
        return {"status": "success", "encrypted": encrypted.serialize()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/sum")
async def compute_sum(encrypted_arrays: List[Dict[str, Any]]):
    """Compute the sum of encrypted arrays."""
    try:
        # Deserialize encrypted data
        encrypted = [ppc.he.context.deserialize(e['data']) for e in encrypted_arrays]
        result = ppc.secure_sum(encrypted)
        return {"status": "success", "result": result.serialize()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/average")
async def compute_average(encrypted_arrays: List[Dict[str, Any]]):
    """Compute the average of encrypted arrays."""
    try:
        # Deserialize encrypted data
        encrypted = [ppc.he.context.deserialize(e['data']) for e in encrypted_arrays]
        result = ppc.secure_average(encrypted)
        return {"status": "success", "result": result.serialize()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/weighted-sum")
async def compute_weighted_sum(request: Dict[str, Any]):
    """Compute a weighted sum of encrypted values."""
    try:
        encrypted_arrays = request.get('data', [])
        weights = request.get('weights', [])
        
        if len(encrypted_arrays) != len(weights):
            raise ValueError("Number of encrypted arrays must match number of weights")
            
        # Deserialize encrypted data
        encrypted = [ppc.he.context.deserialize(e['data']) for e in encrypted_arrays]
        result = ppc.secure_weighted_sum(encrypted, weights)
        return {"status": "success", "result": result.serialize()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/polynomial")
async def evaluate_polynomial(request: Dict[str, Any]):
    """Evaluate a polynomial on encrypted data."""
    try:
        encrypted_data = request.get('encrypted_data', {})
        coefficients = request.get('coefficients', [])
        
        # Deserialize encrypted data
        x_encrypted = ppc.he.context.deserialize(encrypted_data['data'])
        result = ppc.secure_polynomial(x_encrypted, coefficients)
        return {"status": "success", "result": result.serialize()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))