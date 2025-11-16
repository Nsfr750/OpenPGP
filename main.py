import os
import sys
import traceback
import builtins
if 'imghdr' not in sys.modules:
    from core.imghdr_shim import imghdr
    sys.modules['imghdr'] = imghdr
    builtins.imghdr = imghdr

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from gui.main_window import MainWindow
from core.logger import log_error, log_info, log_warning, log_exception
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from fastapi.responses import JSONResponse
from typing import Optional
import logging
from pathlib import Path
from core.siem.middleware import SIEMRequestMiddleware
from core.scim.server import SCIMServer
from core.scim.router import scim_router
from core.api.endpoints import privacy as privacy_endpoints
from core.api.endpoints import compliance as compliance_endpoints
from core.compliance import GDPRCompliance, CCPACompliance
from core.storage.compliance_storage import ComplianceStorage  # You'll need to implement this
from core.api.endpoints import compliance as compliance_endpoints
from core.storage import ComplianceStorage
from core.api.endpoints import data_sovereignty

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

app = FastAPI()

# Include SCIM router
app.include_router(scim_router)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add SIEM middleware
app.add_middleware(SIEMRequestMiddleware)

# Initialize SCIM server and store it in the app state
scim_server = SCIMServer(
    app=app,
    base_url=os.getenv("SCIM_BASE_URL", "/scim/v2"),
    auth_method=os.getenv("AUTH_METHOD", "api_key")  # or "oauth2"
)
app.state.scim_server = scim_server

# Import SCIM server
from core.scim.server import SCIMServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OpenPGP SCIM Server",
    description="SCIM 2.0 compliant server for user and group management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Initialize compliance storage
compliance_storage = ComplianceStorage(storage_path="data/compliance")
gdpr_compliance = GDPRCompliance(storage_backend=compliance_storage)
ccpa_compliance = CCPACompliance(storage_backend=compliance_storage)

# Make compliance handlers available to the endpoints
from core.api.endpoints import compliance as compliance_endpoints
compliance_endpoints.gdpr = gdpr_compliance
compliance_endpoints.ccpa = ccpa_compliance
compliance_endpoints.storage = compliance_storage

app.include_router(privacy_endpoints.router)
app.include_router(compliance_endpoints.router)
app.include_router(data_sovereignty.router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
class Settings:
    SCIM_BASE_URL = os.getenv("SCIM_BASE_URL", "/scim/v2")
    AUTH_METHOD = os.getenv("AUTH_METHOD", "api_key")  # or "oauth2"
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

settings = Settings()

# Initialize SCIM server
scim_server = SCIMServer(
    app=app,
    base_url=settings.SCIM_BASE_URL,
    auth_method=settings.AUTH_METHOD
)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "scim_enabled": True,
        "auth_method": settings.AUTH_METHOD
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "OpenPGP SCIM Server",
        "version": "1.0.0",
        "documentation": "/docs",
        "scim_endpoint": settings.SCIM_BASE_URL
    }

# Error handlers
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": "The requested resource was not found."},
    )

@app.exception_handler(500)
async def server_error_exception_handler(request: Request, exc: HTTPException):
    log_error(f"Server error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."},
    )

app.state.data_sovereignty = data_sovereignty.sovereignty_manager

if __name__ == "__main__":
    import uvicorn
    
    # Start the server
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=int(os.getenv("PORT", 8000)),
        reload=settings.DEBUG,
        log_level="info" if not settings.DEBUG else "debug"
    )
    
def global_exception_hook(exc_type, exc_value, exc_tb):
    """Global exception handler that logs uncaught exceptions."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Call the default excepthook for keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    # Log the exception
    log_exception(exc_value)

# Set the exception hook
sys.excepthook = global_exception_hook

def main():
    # Create the Qt Application
    app = QApplication(sys.argv)
    
    # Set application icon
    app_icon = QIcon("assets/icon.png")
    app.setWindowIcon(app_icon)
    
    # Apply Fusion style for a modern look
    app.setStyle('Fusion')
    
    # Set application information
    app.setApplicationName("OpenPGP")
    app.setApplicationVersion("2.2.0")
    app.setOrganizationName("Tuxxle")
    
    # Create and show the main window
    try:
        window = MainWindow()
        window.show()
        
        # Log application start
        log_info("Application started successfully")
        
        # Run the main Qt loop
        return app.exec()
        
    except Exception as e:
        log_error(f"Fatal error: {str(e)}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
