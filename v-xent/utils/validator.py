import re
import ipaddress
import validators
from utils.logger import setup_logger

logger = setup_logger("validator")

class InputValidator:
    """
    Strict input validation for the V-XENT framework.
    Ensures targets follow RFC standards for IPs, Domains, and CIDRs.
    """
    
    @staticmethod
    def is_valid_ip(ip_str):
        """Checks if a string is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_domain(domain_str):
        """Checks if a string is a valid domain name."""
        # validators.domain returns True or ValidationFailure
        return bool(validators.domain(domain_str))

    @staticmethod
    def is_valid_cidr(cidr_str):
        """Checks if a string is a valid CIDR network range."""
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_target(cls, target):
        """
        Global target validation.
        Rejects suspicious patterns and ensures standard formats.
        """
        if not target or not isinstance(target, str):
            return False, "Target inválido o vacío."

        # Strip whitespace and normalize
        target = target.strip().lower()

        # Check for command injection characters or other common payloads
        if any(char in target for char in [';', '&', '|', '`', '$', '<', '>', '{', '}']):
            return False, f"Caracteres maliciosos detectados en el target: {target}"

        # 1. Check IP
        if cls.is_valid_ip(target):
            return True, "IP"

        # 2. Check CIDR
        if "/" in target and cls.is_valid_cidr(target):
            return True, "CIDR"

        # 3. Check Domain
        if cls.is_valid_domain(target):
            return True, "DOMAIN"

        return False, "El target no es una IP, Dominio o CIDR válido."

    @staticmethod
    def sanitize_filename(name):
        """Ensures filenames are safe for use in the filesystem."""
        # Only allow alphanumeric, dots, dashes, and underscores
        return re.sub(r'[^a-zA-Z0-9.\-_]', '_', name)
