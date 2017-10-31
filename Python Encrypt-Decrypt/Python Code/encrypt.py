import os, sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(message, key):
    #While loop to catch keys that are shorter than 32 bytes
        while (len(key) < 32):
            try:
                raise Exception('ValueError')
            except Exception as error:
                print ("This key is", 32-len(key), "character(s) short")
                sys.exit(0)    
    #Converting string key and message into bytes
        bytekey = bytes(key, 'utf-8')
        bytemessage = bytes(message, 'utf-8') 
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_bytemessage = padder.update(bytemessage)
        padded_bytemessage += padder.finalize()
    #Generate IV from system's random generator       
        iv = os.urandom(16)
    #Creating an AES CBC cipher
        cipher = Cipher(algorithms.AES(bytekey), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_bytemessage) + encryptor.finalize()
        return ct, iv

def decrypt(eMessage, iv, key):
    #Converting key into byte version
        bytekey = bytes(key, 'utf-8')
    #Re-creating cipher based on key and IV
        cipher = Cipher(algorithms.AES(bytekey), modes.CBC(iv), default_backend())
    #Decrypting based on cipher
        decryptor = cipher.decryptor()
    #Outputting the original message
        originalByteMessage = decryptor.update(eMessage) + decryptor.finalize()
    #Creating an unpadder
        unpadder = padding.PKCS7(128).unpadder()
    #Removing padding from byte message
        data = unpadder.update(originalByteMessage)
        originalUnpaddedMessage = data + unpadder.finalize()
    #Converting back to string
        originalMessage = originalUnpaddedMessage.decode('utf-8')
        return originalMessage
    
