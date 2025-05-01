"""
MikroTik License Manager

This module provides a class-based interface for managing MikroTik licenses.
"""

from typing import Tuple, Union, Optional
from mikro import *
from config import *

class LicenseError(Exception):
    """Base exception for license-related errors."""
    pass

class InvalidLicenseFormatError(LicenseError):
    """Raised when license format is invalid."""
    pass

class InvalidKeyError(LicenseError):
    """Raised when key format or length is invalid."""
    pass

class LicenseManager:
    """A class for managing MikroTik licenses."""
    
    def __init__(self):
        """Initialize the license manager."""
        self._eddsa_private_key: Optional[bytes] = None
        self._eddsa_public_key: Optional[bytes] = None
        self._kcdsa_private_key: Optional[bytes] = None
        self._kcdsa_public_key: Optional[bytes] = None
    
    def generate_eddsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate an EdDSA keypair for license signing.
        
        Returns:
            Tuple[bytes, bytes]: A tuple containing (private_key, public_key)
        """
        curve = getcurvebyname('Ed25519')
        private_key = ECPrivateKey.eddsa_generate(curve)
        self._eddsa_private_key = private_key.eddsa_encode()
        self._eddsa_public_key = private_key.pubkey.eddsa_encode()
        return self._eddsa_private_key, self._eddsa_public_key
    
    def generate_kcdsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a KCDSA keypair for license signing.
        
        Returns:
            Tuple[bytes, bytes]: A tuple containing (private_key, public_key)
        """
        curve = getcurvebyname('Curve25519')
        private_key = ECPrivateKey.generate(curve)
        self._kcdsa_private_key = Tools.inttobytes_le(private_key.scalar, 32)
        self._kcdsa_public_key = Tools.inttobytes_le(int(private_key.pubkey.point.x), 32)
        return self._kcdsa_private_key, self._kcdsa_public_key
    
    def parse_routeros_license(self, license_str: str, public_key: bytes) -> dict:
        """
        Parse and validate a RouterOS license.
        
        Args:
            license_str (str): The license string to parse
            public_key (bytes): The public key for verification
            
        Returns:
            dict: A dictionary containing the parsed license information
            
        Raises:
            InvalidLicenseFormatError: If license format is invalid
            InvalidKeyError: If public key is invalid
        """
        if not isinstance(public_key, bytes) or len(public_key) != KCDSA_KEY_LENGTH:
            raise InvalidKeyError(f"Public key must be {KCDSA_KEY_LENGTH} bytes")
            
        try:
            slic = license_str.replace(MIKRO_LICENSE_HEADER, '').replace(
                MIKRO_LICENSE_FOOTER, '').replace('\n', '').replace(' ', '')
            lic: bytes = mikro_base64_decode(slic)
            licVal = mikro_decode(lic[:16])
            software_id = int.from_bytes(licVal[:6], 'little')
            nonce_hash = lic[16:32]
            signature = lic[32:64]
            
            return {
                'software_id': {
                    'encoded': mikro_softwareid_encode(software_id),
                    'hex': hex(software_id)
                },
                'routeros_version': licVal[6],
                'license_level': licVal[7],
                'nonce_hash': nonce_hash.hex(),
                'signature': signature.hex(),
                'is_valid': mikro_kcdsa_verify(licVal, nonce_hash+signature, public_key)
            }
        except Exception as e:
            raise InvalidLicenseFormatError(f"Failed to parse license: {str(e)}")
    
    def parse_chr_license(self, license_str: str, public_key: bytes) -> dict:
        """
        Parse and validate a CHR license.
        
        Args:
            license_str (str): The license string to parse
            public_key (bytes): The public key for verification
            
        Returns:
            dict: A dictionary containing the parsed license information
            
        Raises:
            InvalidLicenseFormatError: If license format is invalid
            InvalidKeyError: If public key is invalid
        """
        if not isinstance(public_key, bytes) or len(public_key) != KCDSA_KEY_LENGTH:
            raise InvalidKeyError(f"Public key must be {KCDSA_KEY_LENGTH} bytes")
            
        try:
            slic = license_str.replace(MIKRO_LICENSE_HEADER, '').replace(
                MIKRO_LICENSE_FOOTER, '').replace('\n', '').replace(' ', '')
            lic: bytes = mikro_base64_decode(slic)
            licVal = mikro_decode(lic[:16])
            system_id = int.from_bytes(licVal[:8], 'little')
            nonce_hash = lic[16:32]
            signature = lic[32:64]
            
            return {
                'system_id': {
                    'encoded': mikro_systemid_encode(system_id),
                    'hex': hex(system_id)
                },
                'deadline': licVal[11],
                'level': licVal[12],
                'nonce_hash': nonce_hash.hex(),
                'signature': signature.hex(),
                'is_valid': mikro_kcdsa_verify(licVal, nonce_hash+signature, public_key)
            }
        except Exception as e:
            raise InvalidLicenseFormatError(f"Failed to parse license: {str(e)}")
    
    def generate_routeros_license(self, software_id: Union[str, int], private_key: bytes) -> str:
        """
        Generate a RouterOS license.
        
        Args:
            software_id (Union[str, int]): The software ID (can be string or integer)
            private_key (bytes): The private key for signing
            
        Returns:
            str: The generated license string
            
        Raises:
            InvalidKeyError: If private key is invalid
        """
        if not isinstance(private_key, bytes) or len(private_key) != KCDSA_KEY_LENGTH:
            raise InvalidKeyError(f"Private key must be {KCDSA_KEY_LENGTH} bytes")
            
        if isinstance(software_id, str):
            software_id = mikro_softwareid_decode(software_id)
            
        lic = software_id.to_bytes(6, 'little')
        lic += ROUTEROS_VERSION.to_bytes(1, 'little')
        lic += ROUTEROS_FEATURES.to_bytes(1, 'little')
        lic += b'\0'*8
        sig = mikro_kcdsa_sign(lic, private_key)
        lic = mikro_base64_encode(mikro_encode(lic)+sig, True)
        return MIKRO_LICENSE_HEADER + '\n' + lic[:len(lic)//2] + '\n' + lic[len(lic)//2:] + '\n' + MIKRO_LICENSE_FOOTER
    
    def generate_chr_license(self, system_id: Union[str, int], private_key: bytes) -> str:
        """
        Generate a CHR license.
        
        Args:
            system_id (Union[str, int]): The system ID (can be string or integer)
            private_key (bytes): The private key for signing
            
        Returns:
            str: The generated license string
            
        Raises:
            InvalidKeyError: If private key is invalid
        """
        if not isinstance(private_key, bytes) or len(private_key) != KCDSA_KEY_LENGTH:
            raise InvalidKeyError(f"Private key must be {KCDSA_KEY_LENGTH} bytes")
            
        if isinstance(system_id, str):
            system_id = mikro_systemid_decode(system_id)
            
        lic = system_id.to_bytes(8, 'little')
        lic += CHR_UNKNOWN_VALUE_1.to_bytes(1, 'little')
        lic += CHR_UNKNOWN_VALUE_2.to_bytes(1, 'little')
        lic += CHR_UNKNOWN_VALUE_3.to_bytes(1, 'little')
        lic += CHR_RENEW_DATE.to_bytes(1, 'little')
        lic += CHR_LICENSE_LEVEL.to_bytes(1, 'little')
        lic += b'\0'*3
        sig = mikro_kcdsa_sign(lic, private_key)
        lic = mikro_base64_encode(mikro_encode(lic)+sig, True)
        return MIKRO_LICENSE_HEADER + '\n' + lic[:len(lic)//2] + '\n' + lic[len(lic)//2:] + '\n' + MIKRO_LICENSE_FOOTER 