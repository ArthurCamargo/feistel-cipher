def bacon(message: str, data: bytes) -> [int, bytes]:
    alphabet = {
        'A': '00000',
        'B': '00001',
        'C': '00010',
        'D': '00011',
        'E': '00100',
        'F': '00101',
        'G': '00110',
        'H': '00111',
        'I': '01000',
        'J': '01001',
        'K': '01010',
        'L': '01011',
        'M': '01100',
        'N': '01101',
        'O': '01110',
        'P': '01111',
        'Q': '10000',
        'R': '10001',
        'S': '10010',
        'T': '10011',
        'U': '10100',
        'V': '10101',
        'W': '10110',
        'X': '10111',
        'Y': '11000',
        'Z': '11001'
    }


    bin = ''
    encoded = ''
    message = message.upper()
    data = data.upper()
    for letter in message:
        if letter in alphabet:
            bin += alphabet[letter]

    print(bin)
    i = 0
    j = 0
    while i < len(bin):
        new_letter = ''
        letter = data[j]
        if chr(letter) in alphabet.keys():
            if bin[i] == '1':
                new_letter = '\033[3m'
                new_letter += hex(letter)
                new_letter += '\033[0m'

            i += 1
        j += 1

        encoded += new_letter


    return bin, encoded

def bacon_dec(data: bytes) -> [str, int]:
    alphabet = {
        'A': '00000',
        'B': '00001',
        'C': '00010',
        'D': '00011',
        'E': '00100',
        'F': '00101',
        'G': '00110',
        'H': '00111',
        'I': '01000',
        'J': '01001',
        'K': '01010',
        'L': '01011',
        'M': '01100',
        'N': '01101',
        'O': '01110',
        'P': '01111',
        'Q': '10000',
        'R': '10001',
        'S': '10010',
        'T': '10011',
        'U': '10100',
        'V': '10101',
        'W': '10110',
        'X': '10111',
        'Y': '11000',
        'Z': '11001',
    }

    bin = ''
    message = ''
    substr = ''

    iter = 0
    while iter < len(data):
        if data[iter] == '\x1b':
            bin += '1'
            iter += 9
        elif data[iter] in alphabet.keys():
            bin += '0'

        iter += 1

    # Inverting the alphabet
    alphabet_inverse = {v: k for k, v in alphabet.items()}

    for bit in bin:
        substr += bit
        if substr in alphabet_inverse:
            message += alphabet_inverse[substr]
            substr = ''

    print("MESSAGE", message)

    return message, bin


def autokey (plaintext: bytes, key: str) -> bytes:
    key_extended = key + plaintext[:len(plaintext) - len(key)]
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        value = (plaintext[i] + ord(key_extended[i])) % 256
        ciphertext.append(value)

    return ciphertext

def vigenere(plaintext: bytes, key: str) -> bytes:
    key_extended = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        value = (plaintext[i] + ord(key_extended[i])) % 256
        ciphertext.append(value)

    return ciphertext

def encryption(plaintext, key):
    return vigenere(plaintext, key)


def feistel_round_encrypt(left: bytes, right: bytes, key:str) -> bytes:
    # https://en.wikipedia.org/wiki/Feistel_cipher
    # Li + 1
    lip = right

    # Ri + 1
    rip = bytearray()
    for i in range(len(left)):
        rip.append(left[i] ^ encryption(right, key)[i])

    return lip, rip

def feistel_round_decrypt(left: bytes, right: bytes, key:str) -> bytes:
    # https://en.wikipedia.org/wiki/Feistel_cipher
    # Ri
    rip = left

    # Li
    lip = bytearray()
    for i in range(len(left)):
        lip.append(right[i] ^ encryption(left, key)[i])

    return rip, lip


def apply_padding(data: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(message) % block_size)
    padding = bytes([padding_length] * padding_length)
    return  data + padding

def feistel_encrypt(message: str, key:str, rounds:int = 1, block_size: int = 16) -> bytes:
    message = apply_padding(bytearray(message, 'utf-8'), block_size)
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    res = bytearray()

    for block in blocks:
        mid = len(block) // 2
        left, right = block[:mid], block[mid:]
        for _ in range(rounds):
            left, right = feistel_round_encrypt(left, right, key)
            #print("Round: ", left, right)

        all = left + right
        res.extend(all)

    return res

def feistel_decrypt(message: bytes, key:str , rounds:int =1, block_size: int = 16):
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    res = bytearray()

    print("BLOCKS", blocks)
    for block in blocks:
        print("block len:", len(block))
        mid = len(block) // 2
        left, right = block[:mid], block[mid:]
        for _ in range(rounds):
            left, right = feistel_round_decrypt(left, right, key)
            #print("Round: ", left, right)

            all = right + left
            res.extend(all)

    print("RES", res)
    # Decode removes padding on its own
    text = res.decode()
    return text



message = "Quem tem um fantasma, tem tudo!, Porem, se precisa de um textinho muito mias comprido para ter o texto que eu gostaria de ter, meu deux, que dificil, de ter um bom texto com isso aqui aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
secret_message = "FESTA"
encrypted = feistel_encrypt(message, "KEY")
print("Encrypted:", encrypted)

print( "BACON", bacon(secret_message, encrypted)[1])
print(bacon_dec(bacon(secret_message, encrypted)[1]))


decrypted = feistel_decrypt(encrypted, "KEY")
print("Decrypted:",decrypted)

#print(vigenere_decrypt(cript, "SEG"))

# OBAA
# KEYK

# Li = 0x4f, 0x42
# Ri = 0x41, 0x41

# First round:

# Li = '0x41, 0x41'

#           O ,   B
# Ri = xor([0x4f, 0x42], vigenere('0x41, 0x41', `KEY`))
# Ri = xor([0x4f, 0x42], 0x8c, 0x86)
# Ri = '0xc3, 0xc4'

# cipher_text = ['0xc3, 0xc4, 0x41, 0x41']

# Encrypted:
# [0xc3, 0xc4, 0x41, 0x41]

# Decryption
# 0xc3, 0xc4, 0x41, 0x41

# Ri = 0x41, 0x41
# Li = 0xc3, 0xc4 ^ vigenere('0x41, 0x41', KEY)
# Li = '0xc3, 0xc4' ^ '0x8c', '0x86'
