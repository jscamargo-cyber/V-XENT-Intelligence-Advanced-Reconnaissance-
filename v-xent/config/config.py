import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for V-XENT Framework."""
    
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    VT_API_KEY = os.getenv("VT_API_KEY")
    
    # Scanner Limits
    RATE_LIMIT_QUERIES = int(os.getenv("RATE_LIMIT_QUERIES", 1))
    RATE_LIMIT_PERIOD = int(os.getenv("RATE_LIMIT_PERIOD", 1))
    
    # App Settings
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    VERSION = "1.0.0"
    BANNER = r"""
    __     __     __   _______ _   _ _______ 
    \ \   / /     \ \ / /  ___| \ | |__   __|
     \ \_/ / _____ \ V /| |__ |  \| |  | |   
      \   / |_____| > < |  __|| . ` |  | |   
       | |         / . \| |___| |\  |  | |   
       |_|        /_/ \_\_____|_| \_|  |_|   
    Intelligence Advanced Reconnaissance
    """

    @classmethod
    def validate(cls):
        """Validate that essential API keys are present."""
        missing = []
        if not cls.SHODAN_API_KEY:
            missing.append("SHODAN_API_KEY")
        if not cls.VT_API_KEY:
            missing.append("VT_API_KEY")
        
        if missing:
            print(f"[!] Warning: Missing environment variables: {', '.join(missing)}")
            print("[!] Some modules may not work correctly.")
            return False
        return True
