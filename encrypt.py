#!/usr/bin/python
# coding=utf-8

import sys
import getopt
import os
import struct
# Module PyCrypto
from Crypto.Cipher import AES
# Module hash function
from Crypto.Hash import MD5, SHA256
import Crypto.Util.Counter

blockSize = 2048  # The blockSize is a mutilple of 16
padding = "@"

# ======================= Encrypt =================================


def encrypt(mode, IV, myKey, input_file, output_file):

    if(mode != "ECB" and mode != "CBC" and mode != "CFB" and mode != "OFB" and mode != "CTR"):
        print "Available modes: ECB, CBC, CFB, OFB, CTR."
        print "Choose again!"
        sys.exit()

    if(mode == "ECB"):
        mode = AES.MODE_ECB
    elif (mode == "CFB"):
        mode = AES.MODE_CFB
    elif (mode == "OFB"):
        mode = AES.MODE_OFB
    elif (mode == "CBC"):
        mode = AES.MODE_CBC
    elif (mode == "CTR"):
        mode = AES.MODE_CTR

    myHash = SHA256.new(myKey)
    key = myHash.digest()
    # Make sure IV to be 16 bytes
    myHash = MD5.new(IV)
    IV = myHash.digest()

    if (mode != AES.MODE_CTR):
        encryptor = AES.new(key, mode, IV)
    else:
        ctr = Crypto.Util.Counter.new(128,
                                      initial_value=long(IV.encode("hex"), 16))
        encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)

    filesize = os.path.getsize(input_file)
    # Read and write input_file
    with open(input_file, "rb") as fin:
        with open(output_file, "wb") as fout:
            fout.write(struct.pack('<Q', filesize))
            fout.write(IV)

            # while - do: read and write by block size
            while True:
                block = fin.read(blockSize)
                if len(block) == 0:
                    break
                elif len(block) % 16 != 0:
                    # Add padding
                    block = block + padding * (16 - len(block) % 16)
                fout.write(encryptor.encrypt(block))
    return

# =======================================================


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "m:i:k:")
    except getopt.GetoptError:
        print "encrypt.py –m <mode> -i <IV> –k <key> <input_file> <output_file>"
        sys.exit(2)

    if(len(args) != 2):
        print "encrypt.py –m <mode> -i <IV> –k <key> <input_file> <output_file>"
        sys.exit(2)

    # get input_file and output_file
    input_file = args[0]
    output_file = args[1]

    # Get option
    for opt, arg in opts:
        if opt == "-h":
            print "encrypt.py -m <mode> -i <IV> -k <key> <input_file> <output_file>"
            sys.exit()
        elif opt == "-m":
            mode = arg.upper()
        elif opt == "-i":
            IV = arg
        elif opt == "-k":
            myKey = arg

    # Run encrypt function
    encrypt(mode, IV, myKey, input_file, output_file)

    return
# =================================================================


if __name__ == "__main__":
    main(sys.argv[1:])
