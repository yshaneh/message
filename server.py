#!/usr/bin/python3

import users
import crypt_keys
import socket
import _thread
import sys
import select
import signal
import time
import random
import string

# def randomString(stringLength=256):
#     letters = string.ascii_lowercase
#     return (''.join(random.choice(letters) for i in range(stringLength))).encode()

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    users.save()
    try:
        skt.close()
    except:
        pass
    for i in clients:
        try:
            i.close()
        except:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("press ^C (Ctrl+C) to exit")

IP = "0.0.0.0"
PORT = 5555
clients = []
clients_keys = {}
clients_address = {}
private_key, public_key = crypt_keys.get_keys()
str_public = crypt_keys.public_to_str(public_key)
commands = ["change keys", "change name", "change type", "create users", "mute", "unmute", "kick"]
client_users = {}
client_queue = {}
socket_message_size = 4096
users_muted = {}
code = crypt_keys.generate_code(public_key)

skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
skt.bind((IP, PORT))
skt.listen(100)

print("server start, listen on %s:%d" % (IP, PORT))


def get_conn_by_username(username):
    for i in client_users:
        if client_users[i] == username:
            return conn
    return False


def send_message_to_user(username, message):
    user_conn = get_conn_by_username(username)
    if user_conn:
        send_message(user_conn, message)

def handle_command(command, conn, addr):
    global client_users
    user = client_users[conn]
    if command not in commands:
        send_message(conn, "<server> invail command!")
        return True
    if command == "change keys":
        temp_message = conn.recv(socket_message_size)
        if temp_message:
                print("get public key from %s:%d" % (addr[0], addr[1]))
                clients_keys[conn] = crypt_keys.str_to_public(temp_message)
                return True
        else:
            return False
    elif command == "change name":
        send_message(conn, "insert username of user you want to change...")
        old_username = get_message(conn)[:-1]
        if not old_username:
            return ''
        send_message("insert new username to this user...")
        new_username = get_message(conn)
        if not new_username:
            return ''
        new_username = new_username[:-1]
        message, username = users.change_name(user, old_username, new_username)
        send_message(conn, message)
        send_message_to_user(username, "%s change your name to %s" % (user, username))
    elif command == "change type":
        send_message(conn, "insert username of user you want to change...")
        username = get_message(conn)
        if not username:
            return ''
        username = username[:-1]
        send_message(conn, "insert the type you want the user will be...")
        new_type = get_message(conn)
        if not new_type:
            return ''
        new_type = new_type[:-1]
        message = users.change_type(user, username, new_type)
        send_message(conn, message)
        conn_of_user = get_conn_by_username(username)
        if conn_of_user:
            send_message(conn_of_user, "%s change your type to %s" % (user, new_type))
    elif command == "create user":
        send_message(conn, "insert username to create")
        username = get_message(conn)
        if not username:
            return ''
        username = username[:-1]
        send_message(conn, "insert password to create")
        password = get_message(conn)
        if not password:
            return ''
        password = password[:-1]
        message = users.create_user(user, username, password)
        send_message(conn, message)
    elif command == "mute":
        send_message(conn, "insert username you want to mute")
        username = get_message(conn)
        if not username:
            return ''
        username = username[:-1]
        success, message = users.mute(user, username)
        if success:
            users_muted[username] = True
            send_message_to_user(username, "%s has muted you" % user)
        send_message(conn, message)
    elif command == "unmute":
        send_message(conn, "insert username you want to unmute")
        username = get_message(conn)
        if not username:
            return ''
        username = username[:-1]
        success, message = users.unmute(user, username)
        if success:
            users_muted[username] = False
            send_message_to_user(username, "%s has unmuted you" % user)
        send_message(conn, message)
    elif command == "kick":
        send_message(conn, "insert username you want to kick")
        username = get_message(conn)
        if not username:
            return ''
        username = username[:-1]
        success, message = users.kick(user, username)
        if success:
            conn = get_conn_by_username(username)
            if conn:
                remove(conn, "%s kicked you" % user)
            send_message_to_user(username, "%s has kicked you" % user)
        send_message(conn, message)
        
    

def sign_up(conn):
    success = False
    while not success:
        send_message(conn, "insert username 0")
        print("get username from %s" % addr[0])
        username = get_message(conn)
        #time.sleep(2)
        if not username:
            return False
        username = username[:-1]
        print("receive username '%s' from %s\n" % (username, addr[0]))
        print("get password from %s\n" % addr[0])
        send_message(conn, "insert password1")
        password = get_message(conn)
        #time.sleep(2)
        if not password:
            return False
        password = password[:-1]
        print("receive password '%s' from %s\n" % (password, addr[0]))
        success, message = users.create_user('sign up', username, password)
        if success:
            message += "2"
        else:
            message += "0"
        #time.sleep(4)
        send_message(conn, message)
        if success:
            print("%s successfully created user '%s'\n" % (addr[0], username))
    client_users[conn] = username
    success, message = users.login(username, password)
    return True

def check_code(code, public_key, conn):
    print("you got code %s from client, please check with the server you got the same code as he sent" % code.decode())
    if input("do you got the same code as client sent? (n for no, anything else for yes): ").lower() == 'n' or not crypt_keys.verify_code(code, public_key):
        print("probably someone listen to you, please check it and try again")
        remove(conn)
        return False
    return True
    
def message_with_len(message):
    try:
        message = message.encode()
    except:
        pass
    str_len = str(len(message))
    return ("0" * (3 - len(str_len))).encode() + str_len.encode() + message
    

def extract_messages(message_and_sign):
    global client_queue
    try:
        message_and_sign = message_and_sign.encode()
    except:
        pass
    tmp_len = int(message_and_sign[:3]) + 3
    message = message_and_sign[3:tmp_len]
    message_and_sign = message_and_sign[tmp_len:]
    tmp_len = int(message_and_sign[:3]) + 3
    sign_message = message_and_sign[3:tmp_len]
    message_and_sign = message_and_sign[tmp_len:]
    client_queue[conn] = message_and_sign
    return (message, sign_message)

def login(conn, addr):
    global client_users
    logged = False
    while not logged:
        print("get username from %s" % addr[0])
        send_message(conn, "insert username (or 'sign up' for sign up) 0") # extension 0 tells the client to insert a username
        username = get_message(conn)
        #time.sleep(2)
        if not username:
            return False
        print("username '%s' recived from %s" % (username[:-1], addr[0]))
        username = username[:-1]
        if username == 'sign up':
            print("%s sign up now..." % addr[0])
            return sign_up(conn)
        print("get password from %s" % addr[0])
        send_message(conn, "insert passord1") # extension 1 tells the user to insert a password
        password = get_message(conn)
        #time.sleep(2)
        if not password:
            return False
        password = password[:-1]
        print("password '%s' received from %s" % (password, addr[0]))
        logged, message = users.login(username, password)
        #time.sleep(4)
        send_message(conn, message)
    client_users[conn] = username
    print("%s logged in successfully as %s" % (addr[0], username))
    return True  

def get_message(conn):
    while True:
        if client_queue[conn]:
            message = client_queue[conn]
        else:
            message = conn.recv(socket_message_size)
        if message:
            message, sign_message = extract_messages(message)
            # conn.send(randomString())
            time.sleep(0.1)
            if crypt_keys.check(sign_message, message, clients_keys[conn]):
                return crypt_keys.decrypt(message, private_key).decode()
            else:
                warn = "<server> A message was sent from this address that could not be verified! Note that someone may be trying to send messages on your behalf 3"
                send_message(conn, warn)
        else:
            remove(conn, addr[0] + " disconnected")
            return ''

def handle_client(conn, addr):
    client_queue[conn] = ""
    print("send public key  and code to %s:%d" % (addr[0], addr[1]))
    conn.send(code + str_public)
    print("key is sent")
    print("send to the client code: %s, please check with the clients he got hte same code." % code.decode())
    temp_message = conn.recv(socket_message_size)
    if temp_message:
        print("get public key from %s:%d" % (addr[0], addr[1]))
        clients_keys[conn] = crypt_keys.str_to_public(temp_message[6:])
        if not check_code(temp_message[:6], clients_keys[conn], conn):
            remove(conn, addr[0] + " couldn't prove it's realy him")
            return None
    else:
        remove(conn, addr[0] + " disconnected")
        return None
    clients_address[conn] = addr[0] + ":" + str(addr[1])
    print("key recived")
    # name = get_message(conn)
    # accept = input("%s try to connect to server in name '%s', do aprove? ('y' for yes and everythingelse for no): " %  (clients_address[conn], name))
    # if accept.lower() != 'y':
    #     send_message(conn, 'server refuse to connected! n')
    #     remove(conn, 'you rejected the connection of addres %s' % clients_address[conn]) # extension n to say to the client that connection refused 
    #     return None
    # send_message(conn, 'connected to server y') # extension y to say to the client that connection accepted
    if not login(conn, addr):
        return None
    name = "<" + client_users[conn] + "> "
    send_message(conn, "welcome to my chat room :)\n\n")
    while  True:
        try:
            message = get_message(conn)
            if message:
                if message[-1] == "c":
                    message = message[:-1]
                    print("recive command: " + name + message)
                    if not handle_command(message, conn, addr):
                        remove(conn, addr[0] + " disconnected")
                        return None
                else:
                    message = name + message[:-1]
                print(message)
                send_to_everybody(message, conn)
            elif message == '':
                return None

        except:
            pass



def send_message(conn, message):
    message = crypt_keys.encrypt(message, clients_keys[conn])
    sign_message = crypt_keys.sign(message, private_key)
    message = message_with_len(message) 
    sign_message = message_with_len(sign_message)
    conn.send(message + sign_message)
    # nothing = conn.recv(socket_message_size)
    time.sleep(0.1)

def remove(conn, message):
    print(message)
    conn.close()
    if conn in clients:
        clients.remove(conn)
    try:
        del clients_keys[conn]
    except:
        pass
    if conn in client_users:
        users.logout(client_users[conn])



    

def send_to_everybody(message, conn):
    try:
        if users_muted[client_users[conn]]:
            send_message(conn, "you can't send messages because you are muted")
            return None
    except:
        pass
    for c in client_users:
        if c != conn and c in client_users:
            try:
                send_message(c, message)
            except:
                remove(c, "error")
def server_messages():
    inputs = [sys.stdin]
    while True:
        read, write, error = select.select(inputs, [], [])
        server_message = ""
        for inp in read:
            server_message = sys.stdin.readline().rstrip()
            print("\033[1A\033[K", end="")
            print("<you>", server_message)
            server_message = "<server> " + server_message
            send_to_everybody(server_message, None)

_thread.start_new_thread(server_messages, ())

while True:
    conn, addr = skt.accept()
    clients.append(conn)
    print(str(addr[0]) + " connected")
    _thread.start_new_thread(handle_client, (conn, addr))
