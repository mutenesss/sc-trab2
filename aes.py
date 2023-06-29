sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int('30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int('ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int('34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int('07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int('52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int('6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int('45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int('bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int('c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int('46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int('c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int('6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int('e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int('61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int('9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int('41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

reverse_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int('bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int('34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int('ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int('76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int('d4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int('5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int('f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int('c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int('97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int('e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int('6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int('9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int('b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int('2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int('c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int('e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]

def lookup(byte):
    x = byte >> 4
    y = byte & 15
    return sbox[x][y]


def reverse_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return reverse_sbox[x][y]

def create_matrix_16(s):
    all = []
    for i in range(len(s)//16):
        b = s[i*16: i*16 + 16]
        grid = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                grid[i].append(b[i + j*4])
        all.append(grid)
    return all

def calc_rcon():
    # Calcula a matriz rcon até 0x36
    rcon = [[1, 0, 0, 0]]

    for x in range(1, 10):
        rcon.append([rcon[-1][0]*2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b
    return rcon

def expand_key(key):
    # Expande a chave utilizando o algoritmo apresentado em https://en.wikipedia.org/wiki/AES_key_schedule
    # É calculado apenas a expansão para chave de 128 bits

    rcon = calc_rcon()
    key_grid = create_matrix_16(key)[0]

    for round in range(10):
        last_column = [row[-1] for row in key_grid]
        rotate_last = shift_matrix(last_column)
        sbox_last = [lookup(b) for b in rotate_last]
        rcon_last = [sbox_last[i] ^ rcon[round][i] for i in range(len(rotate_last))]
        for r in range(4):
            key_grid[r] += bytes([rcon_last[r] ^ key_grid[r][round*4]])

        for i in range(len(key_grid)):
            for j in range(1, 4):
                key_grid[i] += bytes([key_grid[i][round*4+j] ^ key_grid[i][round*4+j+3]])

    return key_grid

def this_round_key(expanded_key, round):
  return [row[round*4: round*4 + 4] for row in expanded_key]

def shift_matrix(row, n = 1):
    return row[n:] + row[:n]

def multiply_by_2(v):
    # b(x) para MixColumns
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s


def multiply_by_3(v):
    # b(x) + 1 para MixColumns
    return multiply_by_2(v) ^ v


def mix_columns(grid):
    # MixColumns utilizando o algoritmo apresentado em https://en.wikipedia.org/wiki/Rijndael_MixColumns
    new_grid = [[], [], [], []]
    for i in range(4):
        col = [grid[j][i] for j in range(4)]
        col = [
        multiply_by_2(col[0]) ^ multiply_by_3(col[1]) ^ col[2] ^ col[3],
        multiply_by_2(col[1]) ^ multiply_by_3(col[2]) ^ col[3] ^ col[0],
        multiply_by_2(col[2]) ^ multiply_by_3(col[3]) ^ col[0] ^ col[1],
        multiply_by_2(col[3]) ^ multiply_by_3(col[0]) ^ col[1] ^ col[2],
        ]
        for i in range(4):
            new_grid[i].append(col[i])
    return new_grid

def add_sub_key(block, key):
    r = []
    for i in range(4):
        r.append([])
        for j in range(4):
            r[-1].append(block[i][j] ^ key[i][j])
    return r

def encrypt(key, msg):
    """
    Função motora de encrypt
     - Seguindo o padrão apresentado em https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Definitive_standard , são
     executados 10 rounds de operações, resultando em uma mensagem cifrada de 128 bits.
     - A saída é unificada em um string de bytes, que é retornado pela função. 
    """
    # Adição de padding ao texto e divisão em blocos de 16 bytes
    padding = bytes(16 - len(msg) % 16)
    
    if len(padding) != 16:
        msg += padding

    grids = create_matrix_16(msg)
    expanded_key = expand_key(key)
    temp_grids = []
    round_key = this_round_key(expanded_key, 0)

    # Primeiro round
    for grid in grids:
        temp_grids.append(add_sub_key(grid, round_key))

    grids = temp_grids

    # Rounds 2-9
    for round in range(1, 10):
        temp_grids = []
        
        for grid in grids:
            sub_bytes = [[lookup(val) for val in row] for row in grid]
            shift_rows = [shift_matrix(sub_bytes[i], i) for i in range(4)]
            mix_column = mix_columns(shift_rows)
            round_key = this_round_key(expanded_key, round)
            add_subkey = add_sub_key(mix_column, round_key)
            temp_grids.append(add_subkey)

        grids = temp_grids

    # Round 10
    temp_grids = []
    round_key = this_round_key(expanded_key, 10)

    for grid in grids:
        sub_bytes = [[lookup(val) for val in row] for row in grid]
        shift_rows = [shift_matrix(sub_bytes[i], i) for i in range(4)]
        add_subkey = add_sub_key(shift_rows, round_key)
        temp_grids.append(add_subkey)

    grids = temp_grids

    # Unifica os grids em um string de bytes
    string = return_data(grids)
    return string

def decrypt(key, data):
    """
    Função motora de decrypt
     - Executa a ordem reversa do encrypt visto acima. 
     - Seguindo o padrão apresentado em https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Definitive_standard , são
     executados 10 rounds de operações, resultando em uma mensagem cifrada de 128 bits.
     - A saída é unificada em um string de bytes, que é retornado pela função.
    """

    grids = create_matrix_16(data)
    expanded_key = expand_key(key)
    temp_grids = []
    round_key = this_round_key(expanded_key, 10)

    # Ordem reversa do encrypt - Round 10
    temp_grids = []

    for grid in grids:
        add_subkey = add_sub_key(grid, round_key)
        shift_rows = [shift_matrix(add_subkey[i], -1 * i) for i in range(4)]
        sub_bytes = [[reverse_lookup(val) for val in row]for row in shift_rows]
        temp_grids.append(sub_bytes)

    grids = temp_grids

    # Rounds 9-2
    for round in range(9, 0, -1):
        temp_grids = []

        for grid in grids:
            round_key = this_round_key(expanded_key, round)
            add_subkey = add_sub_key(grid, round_key)
            mix_column = mix_columns(add_subkey)
            mix_column = mix_columns(mix_column)
            mix_column = mix_columns(mix_column)
            # 3 execuções de mix_columns para retornar a matriz ao estado original
            shift_rows = [shift_matrix(mix_column[i], -1 * i) for i in range(4)]
            sub_bytes = [[reverse_lookup(val) for val in row] for row in shift_rows]
            temp_grids.append(sub_bytes)

        grids = temp_grids
        temp_grids = []

    # Round 1
    round_key = this_round_key(expanded_key, 0)

    for grid in grids:
        temp_grids.append(add_sub_key(grid, round_key))

    grids = temp_grids

    # Unifica os grids em um string de bytes
    string = return_data(grids)
    return string

def return_data(x):
    data = []
    for a in x:
        for column in range(4):
            for row in range(4):
                data.append(a[row][column])
    
    i = len(data) - 1
    while data[i] == 0:
        i -= 1
    return bytes(data[:i+1])