import random


def gcm(a, b):
    # MDC = Máximo Divisor Comum
    while b:
        a, b = b, a % b
    return a # returns int


def lcm(a, b):
    # MMC = Mínimo Múltiplo Comum
    return a * b // gcm(a, b) # returns int

def modinv(a, m):
    # Inverso multiplicativo modular
    if gcm(a, m) != 1:
        raise ValueError("Modular inverse does not exist")
    return pow(a, -1, m) # returns int

def miller_rabin_primality(n, rounds = 40):
    """Baseado nas implementações de:
    https://gist.github.com/Ayrx/5884790
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Primality_Testing
    """
    if n == 2:
        return True
    if n & 1 == 0:
        return False
    
    r = 0 
    s = n - 1

    while s & 1 == 0:
        r += 1
        s = s >> 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True # returns bool 

def generate_prime(bits):
    # Gera um número primo aleatório com n bits de tamanho
    while True:
        p = random.randint(2 ** (bits - 1), 2 ** bits - 1)
        if miller_rabin_primality(p):
            return p # returns int

def coprime(a,b):
    # Testa primalidade entre si, mdc(a,b) = 1
    return gcm(a,b) == 1 # returns bool

def rsa_gen_keys():
    # Gera as chaves pública e privada
    p = generate_prime(1024)
    q = generate_prime(1024)

    while p == q:
        q = generate_prime(1024)
    
    n = p * q
    phi = lcm(p - 1, q - 1)

    e = random.randint(2, phi - 1)
    while not coprime(e, phi) and e < phi:
        e = random.randint(2, phi - 1)

    d = modinv(e, phi)
    key = [(e, n), (d, n)]
    return key # returns tuple

def rsa_encrypt(key, message):
    # Criptografa a mensagem com a chave pública
    e, n = key
    message = int.from_bytes(message, 'big')
    return pow(message, e, n) # returns int

def rsa_decrypt(key, message):
    # Descriptografa a mensagem com a chave privada
    d, n = key
    return pow(message, d, n) # returns int


if __name__ == "__main__":
    """ Passagem AES => RSA => AES 
    - Key:  bytes 
    - Data: bytes 
    - encrypt AES => in : bytes => out : bytes
    - encrypt RSA => in : bytes => out : int
    - decrypt RSA => in : int => out : int *Necessario conversao para bytes 
    - decrypt AES => in : bytes => out : bytes

    - Após todos os passos, a mensagem é recuperada com multiplos bytes de lixo no final 
    """
    key = b'string of some more than 16 bytes'
    # data = b'sample message for testing'
    data = b'outra mensagem de teste com tamanho maior'
    result_enc = encrypt(key, data)
    rsa_keys = rsa_gen_keys()
    rsa_enc = rsa_encrypt(rsa_keys[0], result_enc)
    rsa_dec = rsa_decrypt(rsa_keys[1], rsa_enc)
    a = rsa_dec.to_bytes(256, 'big')
    result_dec = decrypt(key, a)
    print(  f'mensagem: {data}\n'
            f'AES enc: {result_enc}\n'
            f'RSA enc: {rsa_enc}\n'
            f'RSA dec: {rsa_dec}\n'
            f'AES dec: {result_dec}')