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

print(f"len(plain) = {finalLength}")
aes.AES_init_ctx(ctxB, keyB)
print("Key:")
hexDump(key)
print("Plaintext:")
hexDump(plainB[0:finalLength])
aes.AES_ECB_encrypt_buffer(ctxB, plainB, finalLength)
print("Encrypted:")
hexDump(plainB[0:finalLength])
aes.AES_ECB_decrypt_buffer(ctxB, plainB, finalLength)
print("Decrypted:")
hexDump(plainB[0:finalLength])

