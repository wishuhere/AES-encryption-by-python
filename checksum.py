#!/usr/bin/python
# coding=utf-8

import sys
import getopt
# Module PyCrypto, Hash
from Crypto.Hash import SHA256, MD5, SHA

blockSize = 1024*1024  # The blockSize is a mutilple of 16

# ================ Checksum =================


def checksum(hash, checksum, input_file):

    print "Hash mode:", hash
    if (hash != "SHA256" and hash != "MD5" and hash != "SHA" and hash != "SHA1" and hash != "SHA-1"):
        print "Available modes: SHA256, MD5, SHA."
        print "Choose again!"
        sys.exit()

    if (hash == "SHA256"):
        hash = SHA256
    elif (hash == "MD5"):
        hash = MD5
    elif (hash == "SHA" or hash == "SHA1" or hash == "SHA-1"):
        hash = SHA

    # Create object myHash
    myHash = hash.new()

   # Read input file
    with open(input_file, "rb") as fin:
        while True:
            block = fin.read(blockSize)
            if len(block) == 0:
                break
            myHash.update(block)

    # Calculate checksum
    hash = myHash.hexdigest()
    if(checksum != None):
        return checksum == hash
    else:
        return hash


# ======================================================
def main(argv):
    myChecksum = None
    try:
        opts, args = getopt.getopt(argv, "h:c:")
    except getopt.GetoptError:
        print "checksum.py -h <hash> -c <checksum> <inputfile>"
        sys.exit(2)

    # Get option
    for opt, arg in opts:
        if opt == "-h":
            hash = arg.upper()
        elif opt == "-c":
            myChecksum = arg

    # If the agruments after removed options
    # not look like: "checksum.py <input_file>"
    if(len(args) != 1):
        print("checksum.py -h <hash> -c <checksum> <inputfile>")
        sys.exit(2)

    # Get input_file
    input_file = args[0]

    # Run checksum function
    flag = checksum(hash, myChecksum, input_file)
    if(flag == True or flag == False):
        print "Result:", flag
    else:
        print "Checksum is created:", flag
    return flag
# =================================================================


if __name__ == "__main__":
    main(sys.argv[1:])
