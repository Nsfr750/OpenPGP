"""
Configuration settings for OpenPGP application.
"""
import os
from typing import Dict, Any
import json
from pathlib import Path

class Config:
    """Application configuration manager."""
    
    _instance = None
    _config: Dict[str, Any] = {
        'enable_tpm': True,  # Global TPM support flag
        'tpm_required': False,  # Whether TPM is required for operation
        'tpm_library': 'auto',  # 'auto', 'tpm2-pytss', or 'custom'
        'log_level': 'INFO',
    }
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self) -> None:
        """Load configuration from file if it exists."""
        config_path = self._get_config_path()
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    self._config.update(loaded_config)
            except (json.JSONDecodeError, IOError) as e:
                import logging
                logging.warning(f"Error loading config: {e}")
    
    def _save_config(self) -> None:
        """Save current configuration to file."""
        config_path = self._get_config_path()
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except IOError as e:
            import logging
            logging.error(f"Error saving config: {e}")
    
    def _get_config_path(self) -> Path:
        """Get the path to the configuration file."""
        config_dir = Path.home() / '.openpgp'
        return config_dir / 'config.json'
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any, save: bool = True) -> None:
        """Set a configuration value."""
        if key in self._config:
            self._config[key] = value
            if save:
                self._save_config()
        else:
            raise KeyError(f"Unknown configuration key: {key}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Get a copy of the current configuration as a dictionary."""
        return self._config.copy()

# Global configuration instance
config = Config()

def get_config() -> Config:
    """Get the global configuration instance."""
    return config
