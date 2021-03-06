#!/usr/bin/python
# coding=utf-8

import sys
import getopt
import struct
# Module PyCrypto
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
import Crypto.Util.Counter

blockSize = 2048  # The blockSize is a mutilple of 16

# ======================= Decrypt =================================


def decrypt(mode, myKey, input_file, output_file):

    if (mode != "ECB" and mode != "CBC" and mode != "CFB" and mode != "OFB" and mode != "CTR"):
        print "Available modes: ECB, CBC, CFB, OFB, CTR."
        print "Choose again!"
        sys.exit()

    if (mode == "ECB"):
        mode = AES.MODE_ECB
    elif (mode == "CFB"):
        mode = AES.MODE_CFB
    elif (mode == "OFB"):
        mode = AES.MODE_OFB
    elif (mode == "CTR"):
        mode = AES.MODE_CTR
    elif (mode == "CBC"):
        mode = AES.MODE_CBC

    myHash = SHA256.new(myKey)
    key = myHash.digest()

    with open(input_file, "rb") as fin:
        size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]
        size = long(size)
        IV = fin.read(16)

        if (mode != AES.MODE_CTR):
            decryptor = AES.new(key, mode, IV)
        else:
            ctr = Crypto.Util.Counter.new(
                128, 			              initial_value=long(IV.encode("hex"), 16))
            decryptor = Crypto.Cipher.AES.new(key, AES.MODE_CTR, counter=ctr)

        with open(output_file, "wb") as fout:
            while True:
                block = fin.read(blockSize)
                if len(block) == 0:
                    break
                content = decryptor.decrypt(block)
                fout.write(content)
            fout.truncate(size)  # Remove padding
    return

# ===========================================================


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "m:k:")
    except getopt.GetoptError:
        print "decrypt.py –m <mode> -k <key> <infile> <outfile>"
        sys.exit(2)

    if(len(args) != 2):
        print "decrypt.py –m <mode> -k <key> <input_file> <output_file>"
        sys.exit(2)

    # get input_file and output_file
    input_file = args[0]
    output_file = args[1]

    # Getoption
    for opt, arg in opts:
        if opt == "-h":
            print "decrypt.py c–m <mode> -k <key> <infile> <outfile>"
            sys.exit()
        elif opt == "-m":
            mode = arg.upper()
        elif opt == "-k":
            myKey = arg

    # Run decrypt function
    decrypt(mode, myKey, input_file, output_file)
    return
# =================================================================


if __name__ == "__main__":
    main(sys.argv[1:])
