import argparse


ALPHABET = {
    "A": "00000",
    "B": "00001",
    "C": "00010",
    "D": "00011",
    "E": "00100",
    "F": "00101",
    "G": "00110",
    "H": "00111",
    "I": "01000",
    "J": "01001",
    "K": "01010",
    "L": "01011",
    "M": "01100",
    "N": "01101",
    "O": "01110",
    "P": "01111",
    "Q": "10000",
    "R": "10001",
    "S": "10010",
    "T": "10011",
    "U": "10100",
    "V": "10101",
    "W": "10110",
    "X": "10111",
    "Y": "11000",
    "Z": "11001",

}


def bacon(plaintext: bytes, key: str, alphabet: dict) -> bytes:
    #For the purpose of encryption, the bacon cipher is used
    #for adding the "key" (or hidden message), inside of the text, adding more
    #randomness to the cipher

    ciphertext = bytearray()
    bin_array = bytearray()

    # Translate the key to an binarray
    for i in range(len(key)):
        if(key[i] in alphabet.keys()):
            value = int(alphabet[key[i]], 2).to_bytes()
            bin_array += value

    for i in range(len(plaintext)):
        # Add them up
        if(i < len(bin_array)):
            value = (plaintext[i] + bin_array[i]) % 256
        else:
            value = plaintext[i]

        ciphertext.append(value)


    return ciphertext


def autokey (plaintext: bytes, key: str) -> bytes:
    # Autokey simple (receives 'auto' key)
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        value = (plaintext[i] + ord(key[i])) % 256
        ciphertext.append(value)

    return ciphertext

def vigenere(plaintext: bytes, key: str) -> bytes:
    # More generic Vigenere (All 256 value characters table)
    key_extended = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        value = (plaintext[i] + ord(key_extended[i])) % 256
        ciphertext.append(value)

    return ciphertext

def encryption(plaintext, key):
    # 3 types of keys, key for vigenere, key for autokey, key for bacon
    return bacon(autokey(vigenere(plaintext, key[0]), key[1]), key[2], ALPHABET)


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

    return lip, rip

def apply_padding(data: bytes, block_size: int) -> bytes:
    # PCKS 7
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return  data + padding

def remove_padding(data: bytes) -> bytes:
    padding_length = data[len(data) - 1]
    data = data[:-padding_length]
    return data

def feistel_encrypt(message: str, key:str, rounds:int = 16, block_size: int = 16) -> bytes:
    message = apply_padding(bytearray(message, 'utf-8'), block_size)
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    res = bytearray()

    for block in blocks:
        mid = len(block) // 2
        left, right = block[:mid], block[mid:]
        for i in range(rounds):
            left, right = feistel_round_encrypt(left, right, key)

        all =  left + right
        res.extend(all)

    return res

def feistel_decrypt(message: bytes, key:str , rounds:int = 16, block_size: int = 16) -> str:
    blocks = [message[i:i + block_size] for i in range(0, len(message), block_size)]
    res = bytearray()

    for block in blocks:
        mid = len(block) // 2
        left, right = block[:mid], block[mid:]
        for i in range(rounds):
            left, right = feistel_round_decrypt(left, right, key)

        all = left + right
        res.extend(all)


    res = remove_padding(res)
    text = res.decode()
    return text

def read_from_file_or_value(value):
    """ Returns value if file does not exist"""
    read_mode = 'r'
    try:
        with open(value, read_mode) as file:
            return file.read().strip()
    except FileNotFoundError:
        return value

parser = argparse.ArgumentParser(description="Encrypt or Decrypt a message using Bacon, Vigenere and Autokey, providing a key and a secret message")
parser.add_argument("--key", required=True, help="Encryption/Decryption key for Vigenere and Autokey, can be a value or a path to a file")
parser.add_argument("--secret", required=True, help="Secret to be combined with the key for Bacon chipher, can be the value or a path to a file")
parser.add_argument("--message", required=True, help="Path to file that contains the message")
parser.add_argument("--mode", required=True, choices=['e', 'd'], help="Modes: 'e' for encryption, 'd' for decryption")

args = parser.parse_args()

mode = args.mode

key = read_from_file_or_value(args.key)
secret = read_from_file_or_value(args.secret)

#Read binary with mode is 'd' (decryption)
message = read_from_file_or_value(args.message)

#Generate autokey (don't want to change at each itaration of the feistel chain)
autokey_key = key + message[len(key):]

# Compose the key into a tuple for easier access
key = (key, autokey_key, secret)


if mode == 'e':
    encrypted = feistel_encrypt(message, key)
    print(encrypted.hex())

elif mode == 'd':
    decrypted = feistel_decrypt(bytearray.fromhex(message), key)
    print(decrypted)


# Testings

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
