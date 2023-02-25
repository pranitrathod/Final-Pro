"""

This python file is a part of an open-source
project Colossus (https://github.com/Kiinitix/Colossus).

Implementation of Hybrid Cryptography (AES + RSA)

Required fields -> file location for encrypting the content of the text file

"""

import euclid
import mail
from configparser import ConfigParser
import secrets
from Cryptodome.Cipher import AES
from Cryptodome import Random
import stego
import dy

def mainMenu():
    print("\n******************************************************************")
    print("******************************************************************")
    print("Welcome...")
    print("We're going to encrypt and decrypt a message using AES")
    print("******************************************************************")
    print("******************************************************************\n")

    #configur = ConfigParser()
    #configur.read('configurations.ini')
    #location = configur.get('SMTPlogin', 'file_location')

    # Obtains public key.
    print("Genering RSA public and Privite keys......")
    pub,pri=euclid.KeyGeneration()

    # Generates a fresh symmetric key for the data encapsulation scheme.
    print("Genering AES symmetric key......")
    key = secrets.token_hex(16)
    KeyAES=key.encode('utf-8')

    # Encrypts the message under the data encapsulation scheme, using the symmetric key just generated.
    plainText = input("Enter the message: ")
    cipherAESe = AES.new(KeyAES,AES.MODE_GCM)
    nonce = cipherAESe.nonce

    print("Encrypting the message with AES......")
    cipherText=euclid.encryptAES(cipherAESe,plainText)
    src = input(r"Enter image source: ")
    stego.Encode(src, cipherText, src)

    print("Successfully encrypted and hidden the text in picture......")

    # Encrypt the symmetric key under the key encapsulation scheme, using Alice’s public key.
    cipherKey=euclid.encrypt(pub,key)
    print("Encrypting the AES symmetric key with RSA......")

# ------------------------------------------------------------------------------------------------------------------------------------
# NOTE:REMEMBER SECRET KEY CAN MAKE THE DIFFERENCE HERE IF WE HAVE A SECRET KEY WE CAN USE IT TO DECRY/ENCRY,HENCED A HYBRID ECC+AES
 
#NOTE:REMEMBER SECRET KEY CAN MAKE THE DIFFERENCE HERE IF WE HAVE A SECRET KEY WE CAN USE IT TO DECRY/ENCRY,HENCED A HYBRID ECC+AES
 

from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# msg = b'Pranits Text to be encrypted by ECC public key and ' \
#       b'decrypted by its corresponding ECC private key'
msg=input("enter a msg").encode('ASCII')
print("original msg:\n", msg)
print()
privKey = secrets.randbelow(curve.field.n)
print("Private Key",privKey)
pubKey = privKey * curve.g

encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print()
print("encrypted msg:\n", encryptedMsgObj)
print()

# decryptedMsg = decrypt_ECC(encryptedMsg,privKey)
# print("decrypted msg:\n", decryptedMsg)

#------------------------------------------------------------------------------------------------------------------------------------

#sending mail

# mail.mail(privKey,encryptedMsg[0],encryptedMsg[1],encryptedMsg[2],encryptedMsg[3])
mail.mail(privKey,encryptedMsgObj)
dy.decrypt_ECC(encryptedMsg,privKey)
#mail.mail(pri, cipherKey, nonce,src)