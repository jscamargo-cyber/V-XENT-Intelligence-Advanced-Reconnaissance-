import hmac
import hashlib
import json
import os
from config.config import Config

class IntegrityManager:
    """
    Ensures the integrity of generated reports using HMAC-SHA256.
    """
    
    @staticmethod
    def _get_secret():
        """
        Uses the SHODAN_API_KEY as a salt/key for HMAC if no dedicated key is provided.
        In production, a dedicated SECRET_KEY should be used.
        """
        secret = os.getenv("V_XENT_SECRET", Config.SHODAN_API_KEY or "default_secret_key")
        return secret.encode()

    @classmethod
    def sign_report(cls, report_dict):
        """
        Adds an HMAC signature to the report dictionary.
        """
        report_copy = report_dict.copy()
        # Remove old signature if present
        report_copy.pop("integrity_hash", None)
        
        # Serialize to a consistent string
        report_content = json.dumps(report_copy, sort_keys=True).encode()
        
        # Generate HMAC
        signature = hmac.new(
            cls._get_secret(),
            report_content,
            hashlib.sha256
        ).hexdigest()
        
        report_dict["integrity_hash"] = signature
        return report_dict

    @classmethod
    def verify_report(cls, report_dict):
        """
        Verifies the HMAC signature of a report.
        """
        if "integrity_hash" not in report_dict:
            return False
        
        signature_to_verify = report_dict.pop("integrity_hash")
        report_content = json.dumps(report_dict, sort_keys=True).encode()
        
        expected_signature = hmac.new(
            cls._get_secret(),
            report_content,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature_to_verify, expected_signature)
        
