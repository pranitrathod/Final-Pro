from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# privKey=input('ENTER PrivateKey')
# ciphertext=input('ENTER CIPERTEXT').encode('ASCII')
# nonce=input('ENTER NONCE').encode('ASCII')
# authTag=input('ENTER AUTHTAG').encode('ASCII')
# # ciphertextPubKey=hex(int(input('ENTER CIPERTEXTPUBKEY')))
# # print(type(ciphertextPubKey))
# sharedECCKey = privKey * 0x47a03ca554b20716bd230cb56d4640910cfb41302b0114fc884567d581ab69091
# secretKey = ecc_point_to_256_bit_key(sharedECCKey)
# plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    # print("!!!!!!!!!!!!!!!!!!!!!!DECRYPTED USING ECC!!!!!!!!!!!!!!!!!!!!!!!---",plaintext)
