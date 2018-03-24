import ConfigParser
import base64
import sys
import socket
import select
import os
import hashlib
import signal
import title
from random import choice
from time import sleep
from col import Colours as C
from col import Colours_list as Rcolour
from Crypto.Cipher import AES

# problem with logout status

"""				
				# improvements to be made #
1. want to make it so that rather than showing peoples ip addresses having joined
	or left, it shows their set username/nickname ( DONE )
2. more colours
3. prevetion of 'return key spamming' 
"""

# global radomly chosen colour from list (Rcolour)
myColour = choice(Rcolour()) 
os.system("clear")
# global padding will be used for encryption and decryption
padding = "#"
# global block size
block_size = 32
# global determines a user has quit
logout_status = 0
#global host and port #testing
host = "127.0.0.1"
port = 4444

def sigint_handler(signum, frame):
	message = "\n{}quitting session......{}\n".format(myColour, C.end)
	for char in message:
		sys.stdout.write(char)
		sys.stdout.flush()
		sleep(0.05)
	sleep(0.8)
	print("{}GOODBYE {}{}".format(myColour, sys.argv[4].upper(), C.end))
	sleep(0.4)
	sys.exit()	
signal.signal(signal.SIGINT, sigint_handler)

def hasher(usr_pwd):
	hash_obj = hashlib.sha512(usr_pwd)
	hexd_obj = hash_obj.hexdigest()
	hash_obj = hashlib.md5(hexd_obj)
	hex_value = hash_obj.hexdigest()
	return hex_value
 
def encrypt(pwd,data):
	pad = lambda s: s + (block_size - len(s) % block_size) * padding #changed
	encode_aes = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	cipher = AES.new(pwd)
	encoded = encode_aes(cipher, data)
	return encoded

def decrypt(pwd,data):
	pad = lambda s: s + (block_size - len(s) % block_size) * padding
	decode_aes = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(padding)
	cipher = AES.new(pwd)
	decoded = decode_aes(cipher, data)
	return decoded

def cia_chat():
	global logout_status
	if(len(sys.argv) < 5):
		print("Usage : python cia_chat.py <server addr> <port> <password> <username>")
		sys.exit()
	host = sys.argv[1]
	port = int(sys.argv[2])
	set_pwd = sys.argv[3]
	set_pwd = hasher(set_pwd)	
	uname = sys.argv[4]
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
	try:
		sock.connect((host, port))
		sock.send("{}{}{}".format(myColour, uname, C.end))
	except:
		print("{}[!] Unable to connect to server, check all paremeters{}".format(C.red, C.end))
		sys.exit()
	title.Title()
	print("Username set to {}; your colour is [{}colour{}]".format(uname, myColour, C.end))
	sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()
	while True:
		socket_list = [sys.stdin, sock]
		read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
		for s in read_sockets:
			if s == sock:
				data = s.recv(4096)
				if not data :
					print("{}\nDisconnected from chat server{}".format(C.red, C.end))
					sys.exit()
				else :
					data = decrypt(set_pwd,data)
					sys.stdout.write(data)
					sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()
			else:
				msg = sys.stdin.readline()
				msg = "{}<{}> {}{}".format(myColour, uname, msg, C.end)
				user_name = msg.split(" ")[0]
				msg = encrypt(set_pwd,msg)
				sock.send(msg)
				sys.stdout.write("{}\nMe >> {}".format(C.red, C.end)); sys.stdout.flush()

if __name__ == "__main__":
    cia_chat()
