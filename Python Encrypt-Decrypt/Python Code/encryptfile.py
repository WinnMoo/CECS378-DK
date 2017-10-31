import os, sys, io
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from array import array

def MyfileEncrypt(filepath):
    #Open file as a byte array
        with open(filepath, "rb") as f:
            byte_array = bytearray(f.read())
            byte_Astring = bytes(byte_array)
    #Generating key and iv
        key = os.urandom(32)
        iv = os.urandom(16)
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_BAstring = padder.update(byte_Astring)
        padded_BAstring += padder.finalize()
    #Creating AES CBC cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_BAstring) + encryptor.finalize()
    #Getting file extension
        ext = filepath[-4:]
        return ct, iv, key, ext 

def MyfileDecrypt(ct, iv, key, saveFilepath):
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypt file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(256).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()
