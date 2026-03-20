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
        # Using a deterministic but "secret" key from env or fallback
        secret = os.getenv("V_XENT_SECRET", Config.SHODAN_API_KEY or "default_secret_key")
        return secret.encode()

    @classmethod
    def sign_report(cls, report_dict):
        """
        Adds an HMAC signature to the report dictionary.
        """
        # Create a copy to avoid side effects
        report_copy = report_dict.copy()
        report_copy.pop("integrity_hash", None)
        
        # Consistent serialization
        report_content = json.dumps(report_copy, sort_keys=True).encode()
        
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
        
        # Defensive copy to avoid modifying the input dict
        report_copy = report_dict.copy()
        signature_to_verify = report_copy.pop("integrity_hash")
        
        # Ensure we don't have other fields added later that weren't in sign_report
        # In this framework, we expect the exact same fields as when signed.
        
        report_content = json.dumps(report_copy, sort_keys=True).encode()
        
        expected_signature = hmac.new(
            cls._get_secret(),
            report_content,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature_to_verify, expected_signature)
