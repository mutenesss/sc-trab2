import hashlib
import base64
from rsa import rsa_encrypt, rsa_decrypt

def sign(msg: bytes, keys):
    # Hash da mensagem inicial
    hash = hashlib.sha3_256(msg).digest()
    sig = rsa_encrypt(keys[0], hash)
    # Assina mensagem e faz encode para base64
    sig = base64.b64encode(sig.to_bytes(256, 'big'))
    return sig

def verify(msg: bytes, sig: bytes, keys):
    # Hash da mensagem inicial
    hash = hashlib.sha3_256(msg).digest()
    # Recebe mensagem assinada e faz decode de base64
    sig = base64.b64decode(sig)
    sig = int.from_bytes(sig, 'big')
    # Calcula hash da assinatura
    hash_sig = rsa_decrypt(keys[1], sig).to_bytes(256, 'big')
    # Remove padding da hash_sig calculada
    for i in range(0, len(hash_sig)):
        if hash_sig[i] != 0:
            hash_sig = hash_sig[i:]
            break
    # Compara hash da mensagem inicial com hash da assinatura
    return hash == hash_sig

