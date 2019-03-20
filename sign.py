#!/usr/bin/python
# coding=utf-8

import sys
import getopt
import os
# Module PyCrypto, Hash
from Crypto.Hash import SHA256, MD5, SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

blockSize = 1024*1024  # The blockSize is a mutilple of 16

# ==================== Sign  ==================


def sign(hash, input_file, file_signed, file_privatekey):
    # Hash mode
    print "Hash mode: ", hash
    if hash != "SHA256" and hash != "MD5" and hash != "SHA" and hash != "SHA1" and hash != "SHA-1":
        print "Available modes: SHA256, MD5, SHA...."
        print "Choose again!"
        sys.exit()

    if(hash == "SHA256"):
        hash = SHA256
    elif (hash == "MD5"):
        hash = MD5
    elif (hash == "SHA" or hash == "SHA1" or hash == "SHA-1"):
        hash = SHA

   # Load private key from file_privatekey in the same folder
    if os.path.isfile(file_privatekey):
        with open(file_privatekey, "r") as fin:
            key = RSA.importKey(fin.read())

    # Create object myHash
    myHash = hash.new()
    with open(input_file, "rb") as fin:
        while True:
            block = fin.read(blockSize)
            if len(block) == 0:
                break
            myHash.update(block)

    hash = myHash

    # Signed by private key
    mySign = PKCS1_v1_5.new(key)
    signature = mySign.sign(hash)

    # Write public key
    with open("public_key.txt", "w") as fout:
        fout.write(key.publickey().exportKey())
        print "Public key:", key.publickey()

    # Write signature on file
    with open(file_signed, "wb") as fout:
        fout.write(signature)
        print "Signature:", signature

    return mySign

# =====================================================


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:")
    except getopt.GetoptError:
        print "sign.py -h <hash> <fileinput> <ten_file_se_ghi_chu_ky> <file_privatekey>"
        sys.exit(2)

    # Get option
    for opt, arg in opts:
        if opt == "-h":
            hash = arg.upper()

    # If the agruments after removed options
    # not look like: "sign.py <fileinput> <file_signed> <file_privatekey>"
    if(len(args) != 3):
        print "sign.py -h <hash> <fileinput> <file_signed> <file_privatekey>"
        sys.exit(2)

    # Get input_file, file_signed and file_privatekey
    input_file = args[0]
    file_signed = args[1]
    file_privatekey = args[2]

    # Run sign function
    flag = sign(hash, input_file, file_signed, file_privatekey)
    return flag

# =================================================================


if __name__ == "__main__":
    main(sys.argv[1:])
