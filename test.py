from ctypes import *
from hexdump import hexDump

aes = CDLL('./aes.dylib')
ctx = bytes(256)
ctxB = cast(ctx, POINTER(c_ubyte))
key = b"YELLOW SUBMARINEENIRAMBUS WOLLEY"
keyB = cast(key, POINTER(c_char))
#plain = b"Oh hai there !  "
plain = b"Hey whassup? This is an unpadded string!"
finalLength = len(plain)
extraLength = aes.padLength(len(plain))
if extraLength > 0:
  plain += bytes(finalLength)
  finalLength += extraLength
plainB = cast(plain, POINTER(c_char))
if finalLength > 0:
  aes.PKCS7(plainB, finalLength, extraLength)

print("\n\nECB\n=====")
aes.AES_init_ctx(ctxB, keyB)
print(" • Key:")
hexDump(key)
print(" • Plaintext:")
hexDump(plainB[0:finalLength])
aes.AES_ECB_encrypt_buffer(ctxB, plainB, finalLength)
print(" • Encrypted:")
hexDump(plainB[0:finalLength])
aes.AES_ECB_decrypt_buffer(ctxB, plainB, finalLength)
print(" • Decrypted:")
hexDump(plainB[0:finalLength])

print("\n\nCBC\n=====")
plain = b"Hey whassup? This is an unpadded string!"
finalLength = len(plain)
extraLength = aes.padLength(len(plain))
if extraLength > 0:
  plain += bytes(finalLength)
  finalLength += extraLength
plainB = cast(plain, POINTER(c_char))
if finalLength > 0:
  aes.PKCS7(plainB, finalLength, extraLength)
print(" • Plaintext:")
hexDump(plainB[0:finalLength])

IV = bytes(16)
ivB = cast(IV, POINTER(c_ubyte))
aes.fillRandom(ivB, 16)
print(" • IV:")
hexDump(key)
aes.AES_init_ctx_iv(ctxB, keyB, ivB)
aes.AES_CBC_encrypt_buffer(ctxB, plainB, finalLength)
print(" • Encrypted:")
hexDump(plainB[0:finalLength])
aes.AES_init_ctx_iv(ctxB, keyB, ivB)
aes.AES_CBC_decrypt_buffer(ctxB, plainB, finalLength)
print(" • Decrypted:")
hexDump(plainB[0:finalLength])

plain = b"Hey whassup? This is an unpadded string!"
finalLength = len(plain)
extraLength = aes.padLength(len(plain))
if extraLength > 0:
  plain += bytes(finalLength)
  finalLength += extraLength
plainB = cast(plain, POINTER(c_char))
if finalLength > 0:
  aes.PKCS7(plainB, finalLength, extraLength)
aes.fillRandom(ivB, 16)
print("\n • IV:")
hexDump(key)
aes.AES_init_ctx_iv(ctxB, keyB, ivB)
aes.AES_CBC_encrypt_buffer(ctxB, plainB, finalLength)
print(" • Encrypted:")
hexDump(plainB[0:finalLength])
aes.AES_init_ctx_iv(ctxB, keyB, ivB)
aes.AES_CBC_decrypt_buffer(ctxB, plainB, finalLength)
print(" • Decrypted:")
hexDump(plainB[0:finalLength])

print("See? With CBC the cipher is different every time.")
