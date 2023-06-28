from aes import *
from rsa import *
from oaep import *

key = b'string of some more than 16 bytes'
# data = b'sample message for testing'
data = b'outra mensagem de teste com tamanho maior'

rsa_keys = rsa_gen_keys()

result_enc = encrypt(key, data) # bytes
oaep_enc = oaep_encode(result_enc, 256)
rsa_enc = rsa_encrypt(rsa_keys[0], oaep_enc)
rsa_dec = rsa_decrypt(rsa_keys[1], rsa_enc)
aux = rsa_dec.to_bytes(256, 'big')
oaep_dec = oaep_decode(aux, 256)
result_dec = decrypt(key, oaep_dec)

print(  f'mensagem: {data}\n'
        f'AES enc: {result_enc}\n'
        f'OAEP enc: {oaep_enc}\n'
        f'RSA enc: {rsa_enc}\n'
        f'RSA dec: {rsa_dec}\n'
        f'OAEP dec: {oaep_dec}\n'
        f'AES dec: {result_dec}')
