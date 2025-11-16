# config.py
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "OpenPGP SCIM Server"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Server settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    
    # SCIM settings
    SCIM_BASE_URL: str = os.getenv("SCIM_BASE_URL", "/scim/v2")
    AUTH_METHOD: str = os.getenv("AUTH_METHOD", "api_key")  # or "oauth2"
    
    # OAuth2 settings (if using OAuth2)
    OAUTH2_INTROSPECTION_URL: str = os.getenv("OAUTH2_INTROSPECTION_URL", "")
    OAUTH2_CLIENT_ID: str = os.getenv("OAUTH2_CLIENT_ID", "")
    OAUTH2_CLIENT_SECRET: str = os.getenv("OAUTH2_CLIENT_SECRET", "")
    
    # API Key settings (if using API key)
    SCIM_API_KEY: str = os.getenv("SCIM_API_KEY", "your-secure-api-key")
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./openpgp.db")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
settings = Settings()