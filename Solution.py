# Github | @1eclerc

# Libraries (for AES, also pycryptodome)

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# AES key given in the Problem
key = b'IUseSecretKeyADU'

# Base64
encrypted_b64 = "y+Qb/8ZgS5ffAhDlXR/BnI6WMd5WEPVIs4kZ51ybESs="

# Converting
print("[1] Base64 decode")
cipher_bytes = base64.b64decode(encrypted_b64)
print("Base64 transform:", cipher_bytes)

# Pycryptodome & AES-128 & ECB
# + PKCS7 padding
def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    try:
        return unpad(decrypted, AES.block_size).decode()
    except:
        return decrypted.decode(errors="ignore")

# AES Decryption
print("\n[2] AES Decryption (ECB, PKCS7)")
aes_plain = aes_decrypt(cipher_bytes, key)
print("AES Decryption output:", aes_plain)

# The ASCII value of each character decrypted with AES is obtained.
# The ASCII value of each character is reduced by 1 because it was increased by 1 during encryption.
# The new ASCII value is converted back into a character.
# The obtained characters are combined to form a new text.

print("\n[3] ASCII -1")
ascii_decoded = ''.join([chr(ord(c) - 1) for c in aes_plain])
print("Output:", ascii_decoded)

# Reversing
print("\n[4] Reverse")
reversed_text = ascii_decoded[::-1]
print("Reversed text:", reversed_text)

# Applying Caesar -7 because Caesar +7 has been used in encryption
def caesar_decrypt(text, shift):
    result = ''
    for char in text:
        if char.isupper():
            result += chr((ord(char) - shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - shift - 97) % 26 + 97)
        else:
            result += char
    return result

# Printing the result of Caesar cipher
print("\n[5] Caesar cipher (shifting: -7)")
original_message = caesar_decrypt(reversed_text, 7)
print("Output:", original_message)

# Original Message
print("\nOriginal Message:", original_message)
