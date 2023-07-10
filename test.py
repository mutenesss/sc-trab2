from aes import *
from rsa import *
from oaep import *
from sign import *

def test_1(key, data):
    result_enc = encrypt(key, data) # bytes
    result_dec = decrypt(key, result_enc) # bytes
    # # Test Case 1
    print(  f'Mensagem: {data}\n'
            f'Cifracao AES: {result_enc}\n'
            f'Decifracao AES: {result_dec}\n'
            f'Chave AES: {key}\n')
    
def test_2(key, data):
    # Test Case 2
    rsa_keys = rsa_gen_keys()

    result_enc = encrypt(key, data) # bytes
    oaep_enc = oaep_encode(result_enc, 256) # bytes
    rsa_enc = rsa_encrypt(rsa_keys[0], oaep_enc) # int
    rsa_dec = rsa_decrypt(rsa_keys[1], rsa_enc) # int
    aux = rsa_dec.to_bytes(256, 'big')
    oaep_dec = oaep_decode(aux, 256) # bytes
    result_dec = decrypt(key, oaep_dec) # bytes

    print(  f'Mensagem: {data}\n'
            f'Cifracao AES: {result_enc}\n\n'
            f'Encode OAEP: {oaep_enc}\n\n'
            f'Cifracao RSA: {rsa_enc}\n\n'
            f'Decifracao RSA: {rsa_dec}\n\n'
            f'Decode OAEP: {oaep_dec}\n\n'
            f'Decifracao AES: {result_dec}\n\n'
            f'Chave AES: {key}\n\n'
            f'Chave RSA: n = {hex(rsa_keys[0][1])}\n\n'
            f'Chave RSA Public: e = {hex(rsa_keys[0][0])}\n\n'
            f'Chave RSA Private: d = {hex(rsa_keys[1][0])}\n\n')

def test_3(key, data):
    # Test Case 3
    rsa_keys_A = rsa_gen_keys()
    rsa_keys_B = rsa_gen_keys()

    result_enc = encrypt(key, data) # bytes
    oaep_enc = oaep_encode(result_enc, 256) # bytes
    rsa_enc_A = rsa_encrypt(rsa_keys_A[1], oaep_enc) # int
    enc_A_bytes = rsa_enc_A.to_bytes(256, 'big')
    rsa_enc_B = rsa_encrypt(rsa_keys_B[0], enc_A_bytes) # int
    rsa_dec_B = rsa_decrypt(rsa_keys_B[1], rsa_enc_B) # int
    rsa_dec_A = rsa_decrypt(rsa_keys_A[0], rsa_dec_B) # int
    aux = rsa_dec_A.to_bytes(256, 'big')
    oaep_dec = oaep_decode(aux, 256) # bytes
    result_dec = decrypt(key, oaep_dec) # bytes

    print(  f'Mensagem: {data}\n'
            f'Cifracao AES: {result_enc}\n\n'
            f'Encode OAEP: {oaep_enc}\n\n'
            f'Cifracao RSA com chave publica A: {rsa_enc_A}\n\n'
            f'Cifracao RSA com chave privada B: {rsa_enc_B}\n\n'
            f'Decifracao RSA com chave publica B: {rsa_dec_B}\n\n'
            f'Decifracao RSA com chave Privada A: {rsa_dec_A}\n\n'
            f'Decode OAEP: {oaep_dec}\n\n'
            f'Decifracao AES: {result_dec}\n\n'
            f'Chave AES: {key}\n\n'
            f'Chave RSA_A: n = {hex(rsa_keys_A[0][1])}\n\n'
            f'Chave RSA_A Public: e = {hex(rsa_keys_A[0][0])}\n\n'
            f'Chave RSA_A Private: d = {hex(rsa_keys_A[1][0])}\n\n'
            f'Chave RSA_B: n = {hex(rsa_keys_B[0][1])}\n\n'
            f'Chave RSA_B Public: e = {hex(rsa_keys_B[0][0])}\n\n'
            f'Chave RSA_B Private: d = {hex(rsa_keys_B[1][0])}\n\n')

def test_4(key, data):
    # Test Case 4
    rsa_keys = rsa_gen_keys()

    result_enc = encrypt(key, data) # bytes
    oaep_enc = oaep_encode(result_enc, 256) # bytes
    signed = sign(oaep_enc, rsa_keys) # int

    print(  f'Mensagem: {data}\n'
            f'Cifracao AES: {result_enc}\n\n'
            f'Encode OAEP: {oaep_enc}\n\n'
            f'Assinatura Gerada: {signed}\n\n')

def test_5(key, data):
    # Test Case 5
    rsa_keys = rsa_gen_keys()

    result_enc = encrypt(key, data) # bytes
    oaep_enc = oaep_encode(result_enc, 256) # bytes
    signed = sign(oaep_enc, rsa_keys) # int
    verify_signed = verify(oaep_enc, signed, rsa_keys) # bool
    if verify_signed:
        print(  f'Assinatura Testada: {signed}\n\n'
                f'Assinatura Válida!\n\n')
    else:
        print(f'Assinatura Inválida!\n\n')
    
aes_key = b'string of some more than 16 bytes'
msg = b'outra mensagem de teste com tamanho maior'

# test_1(aes_key, msg)
# test_2(aes_key, msg)
# test_3(aes_key, msg)
# test_4(aes_key, msg)
# test_5(aes_key, msg)    