import configparser
import base64
import sys
import socket
import select
import os
import hashlib
import signal
import title
from col import Colours as C
from time import sleep
from Crypto.Cipher import AES
	# change
#uname offline
#list of all current users
users = {}

# global padding
padding = "#"

# global block_size
block_size = 32

os.system("clear")
def banner():
		title.Title()

def server_handle(addr, port, server_status):
	cia = "Produced by the CIA-Project"
	for char in cia:
		sleep(0.03)
		sys.stdout.write(char)
		sys.stdout.flush() 
	sleep(0.4)
	info = "\nserver loading..."
	for char in info:
		sleep(0.06)
		sys.stdout.write(char)
		sys.stdout.flush() 
	sleep(2.5)
	if server_status == True:
		more_info = "\nServer created [address: {}][port: {}]\n".format(addr, port)
		for char in more_info:
			sleep(0.05)
			sys.stdout.write(char)
			sys.stdout.flush() 
		sleep(2)
	else:
		print("\nServer error")

# deals with ctrl-C interrupts
def sigint_handler(signum, frame):
    kill_message = "\n{}Shutting down server......{}\n".format(C.red, C.end)
    for char in kill_message:
    	sys.stdout.write(char)
    	sys.stdout.flush()
    	sleep(0.05)
    sleep(0.6)
    sys.exit()	 
signal.signal(signal.SIGINT, sigint_handler)

def hasher(key):
	hash_object = hashlib.sha512(key.encode('utf-8'))
	hexd = hash_object.hexdigest()
	hash_object = hashlib.md5(hexd.encode('utf-8'))
	hex_dig = hash_object.hexdigest()
	return hex_dig

def encrypt(pwd,data):
	pad = lambda s: s + (block_size - len(s) % block_size) * padding
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

config = configparser.RawConfigParser()   
config.read(r'cia-chat.conf')
HOST = config.get('config', 'HOST')
PORT = int(config.get('config', 'PORT'))
PASSWORD = config.get('config', 'PASSWORD')
key = hasher(PASSWORD)
socket_connections = []

def cia_chat():	
	sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	
	sock_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	
	sock_server.bind((HOST, PORT))	
	sock_server.listen(10)	
	socket_connections.append(sock_server)

	server_handle(HOST, str(PORT), True)
	while True:
	    ready_to_read,ready_to_write,in_error = select.select(socket_connections,[],[],0)
	    for sock in ready_to_read:
	        if sock == sock_server:
	            conn, addr = sock_server.accept()
	            socket_connections.append(conn)
	            username = conn.recv(1024)
	            users[str(addr[1])] = username
	            print(users)
	            # at this point if a user has connected, we want to accept a username
	            print("user {} connected".format(addr))
	            display_message(sock_server, conn, encrypt(key,"\n{} Entered our chat room\n".format(username)))
	        else:
	            try:
	                data = sock.recv(4096)
	                data = decrypt(key,data)
	                if data:
	                    display_message(sock_server, sock,encrypt(key,"\r" + data))
	                else:
	                    if sock in socket_connections:
	                        socket_connections.remove(sock)
	                    # need some sort selector which determines which user has left
	                    # we keep supplying same port number to dict
	                    display_message(sock_server, sock,encrypt(key,"\n{} has left the chat room\n".format(users[str(addr[1])])))
	                    print(addr[1])
	            except:
					display_message(sock_server, sock, "\n{} has left the chat room\n".format(users[str(addr[1])]))
					continue
	sock_server.close()

# broadcaster
def display_message(sock_server, sock, message):
    for socket in socket_connections:
        if socket != sock_server and socket != sock :
            try :
                socket.send(message)
            except :
                socket.close()
                if socket in socket_connections:
                    socket_connections.remove(socket)


if  __name__ == "__main__": 
	cia_chat()
