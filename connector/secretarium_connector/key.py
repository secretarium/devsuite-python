from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class Key:
    
    def __init__(self, keyPair: ec.EllipticCurvePrivateKey):
        self._cryptoKeyPair = keyPair
    
    def getCryptoKeyPair(self) -> ec.EllipticCurvePrivateKey:
        return self._cryptoKeyPair

    async def getRawPublicKey(self) -> bytes:
        return self._cryptoKeyPair.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )[1:]
    
    @staticmethod
    async def createKey():
        return Key(ec.generate_private_key(ec.SECP256R1()))
