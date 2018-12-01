import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding
from cryptography.exceptions import InvalidSignature
from pathlib import Path
import constants
import SimpleEncrypt
import KeyGen

#MAC generation and message encryption
def MyEncryptMAC(message, enc_key, HMAC_key):
    
    #check if the size of the key is incorrect
    if len(HMAC_key) != constants.KEY_LENGTH:
        print("ERROR: key is not ", constants.KEY_LENGTH," bytes long.")
        return None, None, None
    
    ciphertext, iv = SimpleEncrypt.MyEncrypt(message, enc_key)
    
    #MAC / tag
    tag = hmac.HMAC(HMAC_key, hashes.SHA256(), backend=default_backend())
    tag.update(ciphertext)
    tag = tag.finalize()
    
    #tag = H(m||H(m||k) ||k)
    #tag is the size of the hash function (SHA256), which is 256 bits
    
    return ciphertext, iv, tag

#MAC verification and message decryption
def MyDecryptMAC(ciphertext, IV, tag, encKey, HMAC_key):
    check = hmac.HMAC(HMAC_key, hashes.SHA256(), backend=default_backend())
    check.update(ciphertext)

    try:#verify that tag is valid
        print("Verifying integrity...")
        check.verify(tag)

        #decryption & unpadding
        message = SimpleEncrypt.MyDecrypt(ciphertext, encKey, IV)
        print("Message verified")
        return message
    except InvalidSignature:
        print("Invalid HMAC tag")
        return None


#--------F I L E   C R Y P T O G R A P H Y--------


#File encryption with MAC generation
def MyFileEncryptMAC(filepath):
    if not os.path.isfile(filepath):
        print("Invalid file path or nonexistent file.")
        return None, None, None, None, None, None
    else:
        #generate random keys
        print("Generating keys...")
        enc_key = KeyGen.generateKey()
        HMACKey = KeyGen.generateKey()

        #open and read the file
        print("Reading in file...")
        file = open(filepath, 'rb')
        plaintext = file.read()
        file.close()

    
        #encrypting the file
        print("Generating MAC and encrypting...")
        ciphertext, IV, tag = MyEncryptMAC(plaintext, enc_key, HMACKey)
  
        #seperating the file name and the file extension
        fileName, fileExt = os.path.splitext(filepath)
    
    
        #write the ciphertext to a new file at the same file path
        print("Writing encryption out...")
        file = open(fileName + constants.ENC_EXT, 'wb')
        file.write(ciphertext)
        file.close()
        
        return ciphertext, IV, tag, enc_key, HMACKey, fileExt

#MAC verification and file decryption
def MyFileDecryptMAC(filepath_out, ciphertext, IV, tag, enc_key, HMACKey, ext):
    #decrypting
    print("Verifying tag and decrypting...")
    plaintext = MyDecryptMAC(ciphertext, IV, tag, enc_key, HMACKey)
    print("Verified and decrypted")

    #open and decrypt image
    print("Writing out decrypted file...")
    decrypt = open(filepath_out, "wb")
    decrypt.write(plaintext)
    decrypt.close()
    return

#simple test designs
def test_pass():

    print("File being encrypted...")
    C, IV, tag, enc_key, HMACKey, ext = MyFileEncryptMAC(constants.IMG_PATH)
    print("File encryption complete")

    print("File being decrypted...")
    MyFileDecryptMAC(constants.DECR_IMG_PATH, C, IV, tag, enc_key, HMACKey, ext)
    print("File decryption complete")
    return

#test_pass()
