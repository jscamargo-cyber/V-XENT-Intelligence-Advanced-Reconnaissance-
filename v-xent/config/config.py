import os
from dotenv import load_dotenv

# Load environment variables from .env file
# override=False ensures system/Docker environment variables take higher precedence
load_dotenv(override=False)

class Config:
    """
    Framework configuration management.
    Loads settings from environment variables and provides defaults.
    """
    
    # API Keys
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    VT_API_KEY = os.getenv("VT_API_KEY")
    
    # Scanner Limits
    RATE_LIMIT_QUERIES = int(os.getenv("RATE_LIMIT_QUERIES", 1))
    RATE_LIMIT_PERIOD = float(os.getenv("RATE_LIMIT_PERIOD", 1.1))
    
    # App Settings
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    VERSION = "1.1.0-secure"
    
    BANNER = r"""
    __     __     __   _______ _   _ _______ 
    \ \   / /     \ \ / /  ___| \ | |__   __|
     \ \_/ / _____ \ V /| |__ |  \| |  | |   
      \   / |_____| > < |  __|| . ` |  | |   
       | |         / . \| |___| |\  |  | |   
       |_|        /_/ \_\_____|_| \_|  |_|   
    Intelligence Advanced Reconnaissance [SECURE]
    """

    @classmethod
    def validate(cls):
        """
        Validates that required configuration is present.
        Returns a list of missing required environment variables.
        """
        missing = []
        if not cls.SHODAN_API_KEY:
            missing.append("SHODAN_API_KEY")
        if not cls.VT_API_KEY:
            missing.append("VT_API_KEY")
        return missing
