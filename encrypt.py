#!/usr/bin/python
# coding=utf-8

#Module co ban
import sys, getopt, os, struct
#Module PyCrypto
from Crypto.Cipher import AES
#Module ham bam hash
from Crypto.Hash import MD5, SHA256
import  Crypto.Util.Counter

blockSize = 2048 #Chon blocksize la boi cua 16
padding = "@"

#=======================Encrypt=================================
def encrypt(mode, myKey, IV, input_file, output_file):

	if( mode != "ECB" and mode != "CBC" and mode != "CFB" and mode != "OFB" and mode != "CTR"):
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
		mode =  AES.MODE_CBC
	elif (mode == "CTR"):
		mode = AES.MODE_CTR

	#Tao key 32bit bang ham bam tu key mac dinh
	myHash = SHA256.new(myKey)
	key = myHash.digest()
	#Bam lai IV thanh 16 bytes
	myHash = MD5.new(IV)
	IV = myHash.digest()
	
	if (mode != AES.MODE_CTR):
		encryptor = AES.new(key, mode, IV)
	else:
		ctr = Crypto.Util.Counter.new(128,
                       initial_value=long(IV.encode("hex"), 16))
		encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)

	filesize = os.path.getsize(input_file)
	#Doc va ghi file
	with open(input_file, "rb") as fin:
		with open(output_file,"wb") as fout:
			fout.write(struct.pack('<Q',filesize))
			fout.write(IV) 

			#while - do: doc va ghi file theo block size
			while True:
				block = fin.read(blockSize)
				#print "Block:", block
				if len(block) == 0:
					break
				elif len(block) % 16 != 0:
					#Them padding
					block = block + padding * (16 -len(block) % 16)
					#print "Block with pads:", block
				fout.write(encryptor.encrypt(block))
	return

#=======================================================
def main(argv):
	#Xu ly tham so dong lenh
	try:
		#getopt.getopt(args, options, [long_options])
		opts, args = getopt.getopt(argv,"m:k:i:")
	except getopt.GetoptError:
		print "encrypt.py –m <mode> –k <key> -i <IV> <input_file> <output_file>"
		sys.exit(2)

	#Neu danh sach tham so sau khi tru di cac option
	#khong phai la dang: "encrypt.py <input_file> <output_file>"
	if(len(args) != 2):
		print "encrypt.py –m <mode> –k <key> -i <IV> <input_file> <output_file>"
		sys.exit(2)

	#Lay thong tin input_file va output_file
	input_file = args[0]
	output_file = args[1]

	#Chay vong for de lay option
	for opt, arg in opts:
		if opt == "-h":
		  print "encrypt.py -m <mode> -k <key> -i <IV> <input_file> <output_file>"
         	  sys.exit()
		elif opt == "-m":
			mode = arg.upper()
		elif opt == "-k":
			myKey = arg
		elif opt == "-i":
			IV = arg
	#---------------Xu ly xong tham so dong lenh-------------------

	#Goi ham ENCRYPT
	encrypt(mode, myKey, IV, input_file, output_file)

	return
#=================================================================

if __name__ == "__main__":
   main(sys.argv[1:])
