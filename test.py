from ctypes import *
from hexdump import hexDump

aes = CDLL('./aes.dylib')
ctx = bytes(256)
ctxB = cast(ctx, POINTER(c_ubyte))
#key = b"YELLOW SUBMARINEENIRAMBUS WOLLEY"
key = bytes(16)
keyB = cast(key, POINTER(c_char))
aes.fillRandom(keyB, 16)

print("\n\nECB\n=====")
for i in range(0, 3):
  plain = b"Hey whassup? This is an unpadded string!\x00"
  finalLength = len(plain)
  extraLength = aes.padLength(len(plain))
  if extraLength > 0:
    plain += bytes(finalLength)
    finalLength += extraLength
  plainB = cast(plain, POINTER(c_char))
  if finalLength > 0:
    aes.PKCS7(plainB, finalLength, extraLength)
  
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
  print("")

print("\n\nCBC\n=====")
plain = b"Hey whassup? This is an unpadded string!\x00"
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

for i in range(0, 3):
  IV = bytes(16)
  ivB = cast(IV, POINTER(c_ubyte))
  aes.fillRandom(ivB, 16)
  print(" • IV:")
  hexDump(ivB[0:16])
  aes.AES_init_ctx_iv(ctxB, keyB, ivB)
  aes.AES_CBC_encrypt_buffer(ctxB, plainB, finalLength)
  print(" • Encrypted:")
  hexDump(plainB[0:finalLength])
  aes.AES_init_ctx_iv(ctxB, keyB, ivB)
  aes.AES_CBC_decrypt_buffer(ctxB, plainB, finalLength)
  print(" • Decrypted:")
  hexDump(plainB[0:finalLength])
  print("")

print("\n\nCTR\n=====")
plain = b"Hey whassup? This is an unpadded string!\x00"
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

for i in range(0, 3):
  IV = bytes(16)
  ivB = cast(IV, POINTER(c_ubyte))
  aes.fillRandom(ivB, 16)
  print(" • IV:")
  hexDump(ivB[0:16])
  aes.AES_init_ctx_iv(ctxB, keyB, ivB)
  aes.AES_CTR_xcrypt_buffer(ctxB, plainB, finalLength)
  print(" • Encrypted:")
  hexDump(plainB[0:finalLength])
  aes.AES_init_ctx_iv(ctxB, keyB, ivB)
  aes.AES_CTR_xcrypt_buffer(ctxB, plainB, finalLength)
  print(" • Decrypted:")
  hexDump(plainB[0:finalLength])
  print("")


print("See? With CBC/CTR the cipher is different every time.")
