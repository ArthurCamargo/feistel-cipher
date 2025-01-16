# Bacon's cypher is an stenography method that utilizes 2 typefaces or different
# types of fonts

import argparse

parser = argparse.ArgumentParser("encrypt")
_ = parser.add_argument('-a', "--alphabet", help="Input file containing the alphabet that\
    will be utilized in the decryption", type=str, required=True)
_ = parser.add_argument('-t', "--text", help="Input file containing the text that\
    will be decrypted", type=str, required=True)
_ = parser.add_argument('-o', "--output", help="Output file that will print the\
    encrypted text", type=str, required=True)
_ = parser.add_argument('-b', "--bin", action='store_true', help="Tells wheter to input the message the\
    binary value being encoded")

args = parser.parse_args()


alphabet = {}

for line in open(args.alphabet):
    line = line.strip()
    tokens = line.split(sep=' ')
    alphabet[tokens[0]] = tokens[1]

text = ''

for line in open(args.text):
    line = line.strip()
    text += line

def decrypt(alphabet, text):
    bin = ''
    msg = ''
    substr = ''

    iter = 0
    while iter < len(text):
        if text[iter] == '\x1b':
            bin += '1'
            iter += 9
        elif text[iter] in alphabet.keys():
            bin += '0'
            iter += 1
        else:
            iter +=1


    # Inverting the alphabet
    alphabet_inverse = {v: k for k, v in alphabet.items()}

    for bit in bin:
        substr += bit
        if substr in alphabet_inverse:
            msg += alphabet_inverse[substr]
            substr = ''

    return msg, bin

msg, bin = decrypt(alphabet, text)

if(args.bin):
    file = open(args.output, 'w')
    file.write(bin + '\n')
    file.close()
else:
    file = open(args.output, 'w')
    file.write( msg + '\n')
    file.close()
