#Importing necessary libaries for this project
import socket
import threading
import rsa
import sqlite3
import hashlib

#Defining IP and Port
HOST = "192.168.1.70"
PORT = 8888
#Defining Public_key size
PUBLIC_KEY_SIZE = 2048

#Creating a class 'ChatServer'
class ChatServer:
    def __init__(self):     #Defining the necessary attribute inside of (__init__) function
        self.clients = {}       #.Saving each clinet username and socket
        self.lock = threading.Lock()   #.handles the client which leave leaves the application
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     #. Creating a TCP IPV4 socket
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   #. Help the server to host on same IP or reuse the address
        self.server.bind((HOST, PORT))                                      #. Binding in IP and Port
        print(f"Server is starting......\n[LISTENING] on {HOST}:{PORT}")    #. Print on Sever Terminal
        self.public_key, self.private_key = rsa.newkeys(PUBLIC_KEY_SIZE)      #. Creating public key and private key of server
        self.usernames = []                                                 #. Stores the authenticate username that enter the application

    def broadcast(self, message, sender_name=None):     #. Creating a function broadcast function for group chat or community chat
        with self.lock:

            for client_name, client_data in self.clients.items():
                if sender_name != client_name:
                    print(message)
                    encrypted_message = rsa.encrypt(message.encode('utf-8'), client_data['public_key'])
                    client_data['socket'].send(encrypted_message)


    def handle_client(self, client_socket, client_address):     #. Creating a function  that handles the multiple if clients
        try:

            public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))         #. Receiving a public key of client

            username = rsa.decrypt(client_socket.recv(1024), self.private_key).decode('utf-8')      #. Receving the usernames

            password = rsa.decrypt(client_socket.recv(1024), self.private_key).decode('utf-8')      #.Receving the password of users


            password = hashlib.sha256(password.encode()).hexdigest()                #. Converting into hash using hashlib libaries
            conn = sqlite3.connect('userdata.db')                                     #. Connecting to database using sqlite3 libaries
            cur = conn.cursor()
            cur.execute('SELECT * FROM userdata WHERE username = ? AND password = ?',(username , password))  #.Checking the user is authenticate or not

            if cur.fetchone():                                                             #. if username and password is true then enter this statement
                print(f"\n{username} [JOINED] chat community :)")

                login = rsa.encrypt("LOGIN".encode('utf-8'), public_key)                    #. Encrypting the message using private key
                client_socket.send(login)                                           #. sending message through client socket

                self.clients[username] = client_socket                         #.adding socket and username
            else:
                failed = rsa.encrypt("FAILED".encode('utf-8'), public_key)      #same things as above
                client_socket.send(failed)


            self.clients[username] = {'socket': client_socket, 'public_key': public_key}    #. Adding clients username with client socket and public key
            self.broadcast(f"\n{username} joined the chat\n", username)


            while True:

                encrypted_message = client_socket.recv(1024)  #. Receving message from client

                if not encrypted_message:               #. For blank message
                    break

                decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')        #. Decrypting the message by private key of server



                def search_user(clients, username_op):          #. Creating a function which search the username and its corresponding socket
                    if username_op in self.clients:
                        return clients[username_op]
                    else:
                        return "NotFound"

                if decrypted_message.lower() == "quit":
                    self.broadcast(f"{username} LEFT THE CHAT!", username)
                    client_socket.close()
                    with self.lock:
                        del self.clients[username]
                    break
                elif '@' in decrypted_message:                      #. This statement is for private chat
                    b = decrypted_message.split("|")                #. if the received message contain '|' then split it separating message and hash
                    if len(b) == 2:                             #. if the split statement contain two elements

                        c = b[0].split('@')                 #. Splitting the message if it contain the '@'
                        print(f"Received hash: {b[1]}")
                        calculate_hash = hashlib.sha256(b[0].encode('utf-8')).hexdigest()       #. Generating hash of received message
                        if calculate_hash == b[1]:                                          #. Checking integrity of message whether the meassage send is original or not

                            msg_hash = hashlib.sha256(c[1].encode("utf-8")).hexdigest()         #. Generating hash of split message

                            combined = f"{c[0]}|{c[1]}|{msg_hash}"                            #.Combining username, message, and hash

                            recipient_socket = search_user(self.clients,c[0])               #. Searching the user by calling a function
                            if recipient_socket:

                                sending_pri = rsa.encrypt(combined.encode("utf-8"), recipient_socket["public_key"]) #. Encrypting the message for client using its own public_key
                                recipient_socket["socket"].send(sending_pri)    #.Sending to specific user using its own scoket

                            else:
                                print("Cannot send")
                        else:
                            print("Message has benn corrupt !!! ")

                    else:
                        print("Message format invalid")
                else:
                    self.broadcast(f"{username}|{decrypted_message}", username)        #. For Community chat System

        except Exception as e:
            print(f"[EXCEPTION] due to {e}")

    def start_server(self):                     #. Function for starting the server
        try:
            self.server.listen()                #. Listening the multiples of clients

            while True:
                client_socket, client_address = self.server.accept()        #. Accepting client connection with socket and address
                print(f"[NEW CONNECTION] from {client_address}!")
                client_socket.send(self.public_key.save_pkcs1("PEM"))       #. Sending public key to each client
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()       #. For handling multiple of clients

        except KeyboardInterrupt:               #. For error handling
            print("Server is terminating...")
            with self.lock:
                for client_data in self.clients.values():
                    client_data['socket'].close()
            self.server.close()

if __name__ == '__main__':
    chat_server = ChatServer()
    chat_server.start_server()
