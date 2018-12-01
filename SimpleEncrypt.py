import os
import constants
import KeyGen
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding
from pathlib import Path

#getting file extension and name
def splitFilename(filepath):
    filename = [f.split('.')[-1] for f in filepath]
    b = ''
    b = b.join(filename[:-1])
    ext = "." + filename[-1]
    return b, ext



#message in byte, not string
#return ciphertext, IV
def MyEncrypt(message, key):
    
    #check if the size of the key is incorrect
    if len(key) != constants.KEY_LENGTH:
        print("ERROR: key is not ", constants.KEY_LENGTH," bytes long.")
        return
    
    #padding the message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(message) + padder.finalize()
    backend = default_backend()
    
    #generate random InitialVector 
    iv = KeyGen.generateIV()
    
    #encrypting the message using AES algorithm with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext, iv
    

#input ciphertext, key, iv
#return plaintext
def MyDecrypt(ciphertext, key, iv):  
    
    #check if the size of the key is incorrect
    if len(key) != constants.KEY_LENGTH:
        print("ERROR: key is not ", constants.KEY_LENGTH, " bytes long.")
        return

    #check if the size of the Initial_Vector is incorrect
    if len(iv) != constants.IV_LENGTH:
        print("ERROR: IV is not ", constants.IV_LENGTH, " bytes long.")
        return

    #decrypting the message, the result is plaintext with padding data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    #unpadding the data from plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    
    #plaintext being returned is in Byte
    return unpadded_plaintext


#--------F I L E   C R Y P T O G R A P H Y--------


#create a new file with encrypted data
#return Ciphertext, IV, Key, extension
def MyFileEncrypt(filePath):
    
    #generate a random key
    key = KeyGen.generateKey()
    
    #open and read the file
    file = open(filePath, 'rb')
    plaintext = file.read()
    file.close()
    
    #encrypting the file
    ciphertext, iv = MyEncrypt(plaintext, key)
  
    #seperating the file name and the file extension
    fileName, fileExt = os.path.splitext(filePath)
    
    
    #write the ciphertext to a new file at the same file path
    file = open(fileName + constants.ENC_EXT, 'wb')
    file.write(ciphertext)
    file.close()
    
    return ciphertext, iv, key, fileExt

#input filePath, original extension, key, iv
#filePath = path of encrypted file 
#create new file with decrypted data
#return the plaintext
def MyFileDecrypt(filePath, ext, key, iv):
    
    #opening the file 
    file = open(filePath, 'rb')
    ciphertext = file.read()
    file.close()
    
    #decrypting the file
    plaintext = MyDecrypt(ciphertext, key, iv)
    
    #seperating the file name and the file extension
    fileName, fileExt = os.path.splitext(filePath)
    
    #write the plaintext to a new file at the same file path
    file = open(fileName + " decrypted" + ext, 'wb')
    file.write(plaintext)
    file.close()
    
    return plaintext

def test():
    #testing MyEncrypt
    key = KeyGen.generateKey()
    ct, iv = MyEncrypt(b"Hello world", key)
    print (ct, iv)
    
    #testing MyDecrypt
    print (MyDecrypt(ct, key, iv))
    
    #testing MyFileEncrypt
    path = "/Users/sovathana/Documents/CECS 378/test/test.jpg"
    ct, iv, key, ext = MyFileEncrypt(path)
    print('\nCiphertext:   ', ct, '\nIV:   ', iv,
          '\nKey:   ', key, '\nExtension:   ',ext)
    
    #testing MyFileDecrypt
    filePath = "/Users/sovathana/Documents/CECS 378/test/test.enc"
    pt = MyFileDecrypt(filePath, ext, key, iv)
    print('\nDecrypted plaintext: ', pt)

#test()
