import os, sys, io
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from array import array

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #Opening file as a byte array
        with open(filepath, 'rb') as f:
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
        ext = filepath[-4:]
    #Reading the key and creating a public key
        with open(RSA_Publickey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                default_backend()
            )
    #Creating a cipher for cipher key
        RSACipher = public_key.encrypt(
            key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label = None
            )
        )
        
        return RSACipher, ct, iv, ext

def MyRSADecrypt(RSACipher, ct, iv, ext, RSA_Privatekey_filepath, saveFilepath):
    #Reading the key and creating a private key
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = default_backend()
            )
    #Decrypting the cipher key with the private key
        key = private_key.decrypt(
            RSACipher,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypting file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()
