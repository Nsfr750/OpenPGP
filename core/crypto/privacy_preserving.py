"""
Privacy-Preserving Computations

This module provides privacy-preserving computation capabilities using homomorphic encryption.
It enables secure computation on encrypted data without needing to decrypt it first.
"""
from typing import List, Dict, Any, Union, Optional, Tuple
import numpy as np
from .homomorphic import HomomorphicEncryption
from ..logger import log_info, log_error, log_warning

class PrivacyPreservingComputations:
    """
    A class for performing privacy-preserving computations using homomorphic encryption.
    """
    
    def __init__(self, he_context: Optional[HomomorphicEncryption] = None):
        """
        Initialize with an optional homomorphic encryption context.
        
        Args:
            he_context: Optional HomomorphicEncryption instance. If None, a default will be used.
        """
        self.he = he_context or HomomorphicEncryption()
        
    def secure_sum(self, encrypted_values: List[Any]) -> Any:
        """
        Securely compute the sum of encrypted values.
        
        Args:
            encrypted_values: List of encrypted values or lists
            
        Returns:
            Encrypted sum of the values
        """
        if not encrypted_values:
            return None
            
        try:
            result = encrypted_values[0].copy()
            for val in encrypted_values[1:]:
                result += val
            return result
        except Exception as e:
            log_error(f"Error in secure_sum: {str(e)}")
            raise
    
    def secure_average(self, encrypted_values: List[Any], count: Optional[int] = None) -> Any:
        """
        Securely compute the average of encrypted values.
        
        Args:
            encrypted_values: List of encrypted values or lists
            count: Optional total count (useful when values are batched)
            
        Returns:
            Encrypted average of the values
        """
        if not encrypted_values:
            return None
            
        try:
            total = self.secure_sum(encrypted_values)
            n = count if count is not None else len(encrypted_values)
            return total * (1.0 / n)  # Multiplication by reciprocal is more efficient than division
        except Exception as e:
            log_error(f"Error in secure_average: {str(e)}")
            raise
    
    def secure_weighted_sum(self, encrypted_values: List[Any], weights: List[float]) -> Any:
        """
        Securely compute a weighted sum of encrypted values.
        
        Args:
            encrypted_values: List of encrypted values or lists
            weights: List of weights (must be the same length as encrypted_values)
            
        Returns:
            Encrypted weighted sum of the values
        """
        if len(encrypted_values) != len(weights):
            raise ValueError("Number of values must match number of weights")
            
        if not encrypted_values:
            return None
            
        try:
            result = encrypted_values[0] * weights[0]
            for val, weight in zip(encrypted_values[1:], weights[1:]):
                result += val * weight
            return result
        except Exception as e:
            log_error(f"Error in secure_weighted_sum: {str(e)}")
            raise
    
    def secure_polynomial(self, x_encrypted: Any, coefficients: List[float]) -> Any:
        """
        Securely evaluate a polynomial on an encrypted value.
        
        Args:
            x_encrypted: Encrypted input value
            coefficients: List of polynomial coefficients [a0, a1, a2, ...] for a0 + a1*x + a2*x² + ...
            
        Returns:
            Encrypted result of the polynomial evaluation
        """
        if not coefficients:
            return None
            
        try:
            # Initialize result with the constant term
            result = self.he.encrypt([coefficients[0]] * len(x_encrypted) if hasattr(x_encrypted, '__len__') else [coefficients[0]])
            
            # If there are more terms, evaluate the polynomial
            if len(coefficients) > 1:
                x_power = x_encrypted.copy()
                result += x_power * coefficients[1]
                
                for coef in coefficients[2:]:
                    x_power *= x_encrypted  # x_power = x_power * x
                    result += x_power * coef
                    
            return result
        except Exception as e:
            log_error(f"Error in secure_polynomial: {str(e)}")
            raise
    
    def secure_dot_product(self, a_encrypted: Any, b_encrypted: Any) -> Any:
        """
        Securely compute the dot product of two encrypted vectors.
        
        Args:
            a_encrypted: First encrypted vector
            b_encrypted: Second encrypted vector
            
        Returns:
            Encrypted dot product
        """
        try:
            # Element-wise multiplication followed by sum
            product = a_encrypted * b_encrypted
            
            # If the result is a vector, sum its elements
            if hasattr(product, '__len__') and len(product) > 1:
                # For CKKS, we can use the rotate and add trick to sum all elements
                result = product.copy()
                n = len(result)
                
                # Sum all elements by rotating and adding log2(n) times
                # This is more efficient than adding n-1 times
                m = 1
                while m < n:
                    rotated = result << m  # Rotate left by m positions
                    result += rotated
                    m *= 2
                
                # The first element now contains the sum of all elements
                return result[0]  # Return just the first element which contains the sum
            else:
                return product
                
        except Exception as e:
            log_error(f"Error in secure_dot_product: {str(e)}")
            raise

    def secure_sigmoid_approximation(self, x_encrypted: Any) -> Any:
        """
        Approximate the sigmoid function on encrypted data using a 3rd degree polynomial.
        This is a privacy-preserving alternative to the standard sigmoid function.
        
        Args:
            x_encrypted: Encrypted input value(s)
            
        Returns:
            Encrypted approximation of sigmoid(x)
        """
        # Coefficients for 3rd degree polynomial approximation of sigmoid
        # sigmoid(x) ≈ 0.5 + 0.197 * x - 0.004 * x^3
        coefficients = [0.5, 0.197, 0.0, -0.004]
        return self.secure_polynomial(x_encrypted, coefficients)
    
    def secure_comparison(self, a_encrypted: Any, b_encrypted: Any) -> Any:
        """
        Securely compare two encrypted values.
        Returns an encrypted 1 if a > b, -1 if a < b, and 0 if a == b.
        
        Note: This is a simplified approach and may not be secure against all attacks.
        For production use, consider using more advanced protocols like GC or FHE comparison.
        """
        try:
            # Compute the difference
            diff = a_encrypted - b_encrypted
            
            # Apply a sigmoid-like function to the difference to get a value between -1 and 1
            # Then round to nearest integer to get -1, 0, or 1
            scaled_diff = diff * 10  # Scale to make the transition sharper
            sigmoid = self.secure_sigmoid_approximation(scaled_diff)
            return (sigmoid * 2) - 1  # Map from [0,1] to [-1,1]
            
        except Exception as e:
            log_error(f"Error in secure_comparison: {str(e)}")
            raise

# Example usage
if __name__ == "__main__":
    # Initialize the privacy-preserving computations
    ppc = PrivacyPreservingComputations()
    
    # Example data
    data1 = [1.5, 2.3, 3.7]
    data2 = [0.7, 1.2, 2.8]
    
    # Encrypt the data
    encrypted1 = ppc.he.encrypt(data1)
    encrypted2 = ppc.he.encrypt(data2)
    
    # Perform privacy-preserving computations
    sum_result = ppc.secure_sum([encrypted1, encrypted2])
    avg_result = ppc.secure_average([encrypted1, encrypted2])
    
    # Decrypt and print results
    print(f"Data 1: {data1}")
    print(f"Data 2: {data2}")
    print(f"Secure sum: {ppc.he.decrypt(sum_result)}")
    print(f"Secure average: {ppc.he.decrypt(avg_result)}")
    
    # Example of polynomial evaluation: 1 + 2x + 3x²
    x = 2.0
    x_enc = ppc.he.encrypt([x])
    poly_result = ppc.secure_polynomial(x_enc, [1.0, 2.0, 3.0])
    print(f"Polynomial 1 + 2*{x} + 3*{x}² = {ppc.he.decrypt(poly_result)[0]}")
    
    # Example of sigmoid approximation
    x_values = [-3, -1, 0, 1, 3]
    for x in x_values:
        x_enc = ppc.he.encrypt([x])
        sigmoid_approx = ppc.secure_sigmoid_approximation(x_enc)
        print(f"Sigmoid({x}) ≈ {ppc.he.decrypt(sigmoid_approx)[0]:.4f}")
