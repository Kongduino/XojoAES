# XojoAES

Sample code showing how to do AES256 (ECB only for now) in Xojo

See [blog post](http://kongduino.sungnyemun.org/2021/06/21/aes256-in-xojo/) for more info.

## C API

```c
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
int padLength(int originalLength);
void PKCS7(uint8_t* buf, int length, uint8_t b);
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_encrypt_buffer(const struct AES_ctx* ctx, uint8_t* buf, int length);
void AES_ECB_decrypt_buffer(const struct AES_ctx* ctx, uint8_t* buf, int length);
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
```

For `_buffer` functions you need to provide a buffer that's a multiple of `AES_BLOCKLEN`, ie 16, preferably properly padded. `padLength` and `PKCS7` can help with that.

## Python demo

### Basic code

```python
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
```


```
% python3 test.py
len(plain) = 48
Key:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
00.|59 45 4c 4c 4f 57 20 53 55 42 4d 41 52 49 4e 45 | |YELLOW SUBMARINE|
01.|45 4e 49 52 41 4d 42 55 53 20 57 4f 4c 4c 45 59 | |ENIRAMBUS WOLLEY|
   +------------------------------------------------+ +----------------+
Plaintext:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
00.|48 65 79 20 77 68 61 73 73 75 70 3f 20 54 68 69 | |Hey whassup? Thi|
01.|73 20 69 73 20 61 6e 20 75 6e 70 61 64 64 65 64 | |s is an unpadded|
02.|20 73 74 72 69 6e 67 21 08 08 08 08 08 08 08 08 | | string!........|
   +------------------------------------------------+ +----------------+
Encrypted:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
00.|9d 41 b3 a3 65 9a 55 0a 0a 54 67 5d 59 ff 69 00 | |.A..e.U..Tg]Y.i.|
01.|33 a8 24 07 bb 63 a4 99 70 ac 4f 9d cc 09 88 95 | |3.$..c..p.O.....|
02.|b1 65 e8 ee ce ed 22 23 43 b6 6a 26 b7 26 65 47 | |.e...."#C.j&.&eG|
   +------------------------------------------------+ +----------------+
Decrypted:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
00.|48 65 79 20 77 68 61 73 73 75 70 3f 20 54 68 69 | |Hey whassup? Thi|
01.|73 20 69 73 20 61 6e 20 75 6e 70 61 64 64 65 64 | |s is an unpadded|
02.|20 73 74 72 69 6e 67 21 08 08 08 08 08 08 08 08 | | string!........|
   +------------------------------------------------+ +----------------+
```