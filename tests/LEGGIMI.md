# Test

## To run the hybrid encryption tests

```code
python -m pytest tests/test_hybrid_crypto.py -v
```

## To test the SCIM server after starting it, you can visit

```code
http://127.0.0.1:8000/scim/v2/.well-known/scim - SCIM service provider configuration
```

```code
http://127.0.0.1:8000/docs - Interactive API documentation (if you enable it)
```

```code
http://127.0.0.1:8000/health - Health check
``` 
