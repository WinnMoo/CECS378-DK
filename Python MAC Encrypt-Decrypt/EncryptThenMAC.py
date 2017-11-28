import os, sys, io, json, base64
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from array import array

def MyencryptMAC(message, encKey, hMacKey):
    #While loop to catch keys that are shorter than 32 bytes
        while (len(encKey) != 32 or len(hMacKey) != 32):
            try:
                raise Exception('ValueError')
            except Exception as error:
                print ("Encryption Key Length:", len(encKey), "byte")
                print ("HMAC Key Length:", len(hMacKey), "byte")
                print ("The key(s) entered is not 32 byte.")
                sys.exit(0)    
    #Converting string key and message into bytes
        byteEncKey = bytes(encKey, 'utf-8')
        byteHMacKey = bytes(hMacKey, 'utf-8')
        byteMessage = bytes(message, 'utf-8') 
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_byteMessage = padder.update(byteMessage)
        padded_byteMessage += padder.finalize()
    #Generate IV from system's random generator       
        iv = os.urandom(16)
    #Creating an AES CBC cipher
        cipher = Cipher(algorithms.AES(byteEncKey), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_byteMessage) + encryptor.finalize()
    #HMAC
        h = hmac.HMAC(byteHMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        tag = h.finalize()
    #Return values
        return ct, iv, tag

def MydecryptMAC(ct, iv, tag, encKey, hMacKey):
    #Converting HMAC key into byte version
        byteHMacKey = bytes(hMacKey, 'utf-8')
    #Verifying tag 
        h = hmac.HMAC(byteHMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        h.verify(tag)
    #Converting encryption key into byte version
        byteEncKey = bytes(encKey, 'utf-8')
    #Re-creating cipher based on key and IV
        cipher = Cipher(algorithms.AES(byteEncKey), modes.CBC(iv), default_backend())
    #Decrypting based on cipher
        decryptor = cipher.decryptor()
    #Outputting the original message
        originalByteMessage = decryptor.update(ct) + decryptor.finalize()
    #Creating an unpadder
        unpadder = padding.PKCS7(128).unpadder()
    #Removing padding from byte message
        data = unpadder.update(originalByteMessage)
        originalUnpaddedMessage = data + unpadder.finalize()
    #Converting back to string
        originalMessage = originalUnpaddedMessage.decode('utf-8')
    #Return values
        return originalMessage

def MyfileEncryptMAC(filepath):
    #Open file as a byte array
        with open(filepath, "rb") as f:
            byte_array = bytearray(f.read())
            byte_Astring = bytes(byte_array)
    #Generating keys and iv
        encKey = os.urandom(32)
        hMacKey = os.urandom(32)
        iv = os.urandom(16)
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_BAstring = padder.update(byte_Astring)
        padded_BAstring += padder.finalize()
    #Creating AES CBC cipher
        cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_BAstring) + encryptor.finalize()
    #Getting file extension
        ext = bytes(filepath[-4:], 'utf-8')
    #HMAC
        h = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        tag = h.finalize()
    #Writing to outfile
        with open(filepath, 'wb') as outfile:
            outfile.write(ct)
            outfile.write(iv)
            outfile.write(tag)
            outfile.write(ext)
    #Return values
        return ct, iv, encKey, hMacKey, tag, ext 

def MyfileDecryptMAC(ct, iv, encKey, hMacKey, tag, ext, saveFilepath):
    #Verifying tag 
        h = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        h.verify(tag)
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypt file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()

def MyRSAEncryptMAC(filepath, RSA_Publickey_filepath):
    #Opening file as a byte array
        with open(filepath, "rb") as f:
            byte_array = bytearray(f.read())
            byte_Astring = bytes(byte_array)
    #Generating key and iv
        encKey = os.urandom(32)
        hMacKey = os.urandom(32)
        iv = os.urandom(16)
    #Padding message
        padder = padding.PKCS7(128).padder()
        padded_BAstring = padder.update(byte_Astring)
        padded_BAstring += padder.finalize()
    #Creating AES CBC cipher
        cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    #Encrypting the cipher
        encryptor = cipher.encryptor()
    #Creating the ciphertext
        ct = encryptor.update(padded_BAstring) + encryptor.finalize()
        ext = bytes(filepath[-4:], 'utf-8')
    #HMAC
        h = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        tag = h.finalize()
    #Reading the key and creating a public key
        with open(RSA_Publickey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                default_backend()
            )
    #Creating a cipher for cipher key
        RSACipher = public_key.encrypt(
            encKey+hMacKey,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label = None
            )
        )
    #Decode bytes into strings
        str_RSACipher = base64.encodestring(RSACipher).decode('utf-8')
        str_ct = base64.encodestring(ct).decode('utf-8')
        str_iv = base64.encodestring(iv).decode('utf-8')
        str_tag = base64.encodestring(tag).decode('utf-8')
        str_ext = ext.decode('utf-8')
        str_concat = str_RSACipher+", "+str_ct+", "+str_iv+", "+str_tag+", "+str_ext
    #Storing encrypted file as a JSON file
        s = json.dumps(str_concat)
        #s = json.dumps(str_RSACipher)+"\n"+json.dumps(str_ct)+"\n"+json.dumps(str_iv)+"\n"+json.dumps(str_tag)+"\n"+json.dumps(str_ext)
        with open(filepath[:-4]+"(encrypted).json", "w") as outfile:
                outfile.write(s)
    #Return values
        return RSACipher, ct, iv, tag, ext

def MyRSADecryptMAC(saveFilepath, RSA_Privatekey_filepath):
    #Reading RSACipher, ct, iv, tag, ext from JSON file
        with open(saveFilepath, "r") as infile:
            file = infile.read()
    #Converting RSACipher, ct, iv, tag into bytes
        f = json.loads(file)
        s = [x for x in f.split(', ')]
        RSACipher = base64.decodestring(bytes(s[0],'utf-8'))
        ct = base64.decodestring(bytes(s[1],'utf-8'))
        iv = base64.decodestring(bytes(s[2],'utf-8'))
        tag = base64.decodestring(bytes(s[3],'utf-8'))
        ext = s[4]
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
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    #Separating concatenated keys
        encKey = key[0:32]
        hMacKey = key[32:64]
    #Verifying tag 
        h = hmac.HMAC(hMacKey, hashes.SHA256(), backend=default_backend())
        h.update(ct)
        h.verify(tag)
    #Re-creating cipher
        cipher = Cipher(algorithms.AES(encKey), modes.CBC(iv), default_backend())
    #Creating decryptor
        decryptor = cipher.decryptor()
    #Decrypting file to byte array
        originalByteFile = decryptor.update(ct) + decryptor.finalize()
    #Removing padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(originalByteFile)
        originalUnpaddedString = data + unpadder.finalize()
    #Saving picture to specified location
        f = open(saveFilepath[:-16]+ext, "wb")
        f.write(bytearray(originalUnpaddedString))
        f.close()

def GenerateRSAKeyPair(RSA_Publickey_filepath, RSA_Privatekey_filepath):
    #Checking if RSA Key Already Exist
        try:
            with open(RSA_Publickey_filepath, "rb") as publicfile:
                print("RSA_Publickey.pem file found at: ", RSA_Publickey_filepath)
            with open(RSA_Privatekey_filepath, "rb") as privatefile:
                print("RSA_Privatekey.pem file found at: ", RSA_Privatekey_filepath)
        except FileNotFoundError as e:
        #Generating private key
            RSA_Privatekey = rsa.generate_private_key(
                public_exponent = 65537,
                key_size = 2048,
                backend = default_backend()
                )
            RSA_Privatekey_pem = RSA_Privatekey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )
        #Generating public key
            RSA_Publickey = RSA_Privatekey.public_key()
            RSA_Publickey_pem = RSA_Publickey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
        #Writing private key and public to file
            with open(RSA_Privatekey_filepath, "wb") as privatefile:
                privatefile.write(RSA_Privatekey_pem)
            with open(RSA_Publickey_filepath, "wb") as publicfile:
                publicfile.write(RSA_Publickey_pem)                         

