#!/usr/bin/python
# coding=utf-8

import sys
import getopt
import struct
# Module PyCrypto
from Crypto.Cipher import AES
# Module hash function
from Crypto.Hash import MD5, SHA256
import Crypto.Util.Counter

# Default key
myKey = "1122334455667788" * 2
blockSize = 1024*1024  # The blockSize is a mutilple of 16

# ==================== Decrypt ==============================


def decrypt(mode, IV, input_file, output_file):

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

    # Create key from default key
    myHash = SHA256.new(myKey)
    key = myHash.digest()
    # Make sure iv to be 16 bytes
    MyHash = MD5.new(IV)
    IV = MyHash.digest()

    with open(input_file, "rb") as fin:
        size = struct.unpack('<Q', fin.read(struct.calcsize('<Q')))[0]

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
            fout.truncate(size)  # remove padding
    return

# ===========================================================


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hm:k:")
    except getopt.GetoptError:
        print "decrypt.py –m <mode> -k <key> <input_file> <output_file>")
            sys.exit(2

    # If the agruments after removed options
    # not look like: "decrypt.py <input_file> <output_file>"
    if(len(args) != 3 or len(args) != 2):
        print "decrypt.py –m <mode> -k <key> <input_file> <output_file>"
        sys.exit(2)

    # Getinput_file va output_file
    input_file = args[0]
    output_file = args[1]

    # Get Option
    for opt, arg in opts:
        if opt == "-h":
        print "decrypt.py –m <mode> -k <key> <input_file> <output_file>"
        sys.exit()
        elif opt == "-m":
            mode = arg.upper()
        elif opt == "-k":
            IV = arg

    # Run decrypt function
    decrypt(mode, IV, input_file, output_file)
    return
# =================================================================


if __name__ == "__main__":
    main(sys.argv[1:])
