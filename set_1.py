# challenge 1
import string

from base64 import b64encode
from binascii import hexlify, unhexlify
from itertools import cycle
from subprocess import check_output
from urllib.request import urlopen

s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

# ascii version
print(bytes.fromhex(s))

# base64 encoded. The `decode` only converts from bytes to str, not really needed
print(b64encode(bytes.fromhex(s)).decode())

# challenge 2
def my_xor(s1, s2):
    """Takes in 2 hex strings, converts to integers, XORs, converts output back to hex"""
    return hex(int(s1, 16) ^ int(s2, 16))
#     return '{:x}'.format(res)  # neater output, without 0x prefix

print(my_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))

# challenge 3
candidates = {}
ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
for s in list(string.ascii_lowercase + string.ascii_uppercase + string.digits):
    val = [c ^ ord(s) for c in bytes.fromhex(ciphertext)]
    # first we check for weird ASCII values
    if (min(val) > 31) & (max(val) < 123):
        res = bytes(val)
        # then we lazily pipe to a spellcheck program, and count the number of errors
        score = int(check_output(f'echo {res} | hunspell -a | grep "&" | wc -l', shell=True).strip())
        candidates[score] = (s, res)
# presumably the minimum one is the winner
print(candidates[min(candidates.keys())])

# challenge 4
with urlopen('https://cryptopals.com/static/challenge-data/4.txt') as f:
    lines = [unhexlify(l.strip()) for l in f.readlines()]

all_combos = [(idx, n, [c^n for c in line]) for idx, line in enumerate(lines) for n in range(256)]

suspects = []
# hunspell method breaks down here. but filtering out weird chars and 
# somewhat weird chars (trial and error led to exact number) works
super_special_chars = set(range(32)).difference([10])
special_chars = super_special_chars.union(range(33, 65)).union(range(91, 97))
for (idx, n, candidate) in all_combos:
    if (len(super_special_chars.intersection(candidate)) == 0) & (max(candidate) < 128):
        if len(set(candidate).intersection(special_chars)) < 4:
            suspects.append((idx, n, bytes(candidate)))
for (idx, n, candidate) in suspects:
    print(f"Line {idx} XOR'd with character {chr(n)} yields '{candidate.decode().strip()}'")

# challenge 5

s = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

print(hexlify(bytes(ord(a) ^ ord(b) for (a,b) in zip(s, cycle('ICE')))))
