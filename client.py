#!/usr/bin/python3

import socket
import select
import sys
import signal
import crypt_keys
import time
import _thread
import random
import string
import threading
#import getch




found_ips = []
threads = {}
checked = 0
commands = ["help", "change keys"]
not_handle_commands = ["mute", "unmute", "change name", "change type", "creat user", "kick"]
connect = False
user_message = ""
queue = ""
socket_message_size = 4096

def print2(message, end="\n"):
    print(message, end=end)
    sys.stdout.flush()

def signal_handler(sig, frame):
    print2('by!\n')
    connect = False
    for i in threads:
        try:
            i.close()
        except:
            pass
    try:
        skt.close()
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)



def handle_commands(command):
    global private_key, public_key, str_public
    if command not in commands:
        if command in not_handle_commands:
            return None
        print2("Invalid command! insert !help for list of commands")
        return None
    if command == "help":
        print2("\ncommands are: \n")
        for i in range(len(commands)):
            print2("%d: %s" % (i+1, commands[i]))

    elif command == "change keys":
        print2("\ngenerate new keys...")
        private_key, public_key = crypt_keys.get_keys()
        str_public = crypt_keys.public_to_str(public_key)
        print2("keys generated")
        print2("send new public key to server...")
        skt.send(str_public)
        print2("public key is sent to the server\n")

    
def message_with_len(message):
    try:
        message = message.encode()
    except:
        pass
    str_len = str(len(message))
    return ("0" * (3 - len(str_len))).encode() + str_len.encode() + message



def animate():
    while checked < len(threads):
        print2("\rscaning network... %0.2f%s" % (checked * 100 / len(threads), "%"), end="")
        time.sleep(0.2)
    print2("\rscaning network... %0.2f%s" % (checked * 100 / len(threads), "%"), end="\n\n")

def choose_ip(found_ips):
    global IP
    number_of_options = len(found_ips)
    if number_of_options == 0:
        print2("There is no ip in your network that listens to port %d" % (PORT))
        IP = input("please insert the server ip: ")
        return None
    for i in range(len(found_ips)):
        print2("%d: %s" % (i+1, found_ips[i]))
    print2("\n\n")
    choise = -1
    while choise < 1 or choise > number_of_options:
        choise = input("choose ip of the above (enter the number of his place on the list): ")
        try:
            choise = int(choise)
            if choise < 1:
                print2("illigal, number is too low!")
            elif choise > len(found_ips):
                print2("illigal, number is too high!")
        except:
            print2("illigal input! you need to insert number")
            choise = -1
    IP = found_ips[choise - 1]


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        raise("can't search because you'r not connected to wifi")
    finally:
        s.close()
    return IP

def is_on(temp_ip):
    global found_ips, checked
    skt_try = socket.socket()
    try:
        skt_try.connect((temp_ip, PORT))
        found_ips.append(temp_ip)
    except:
        pass
    finally:
        skt_try.close()
    checked += 1

def search_on_network():
    global found_ips, threads
    local_ip = get_ip()
    network_ip = local_ip[0:-len(local_ip.split(".")[-1])]
    temp_ip = ""
    skt_try = socket.socket()
    for i in range(1,255):
        temp_ip = network_ip + str(i)
        threads[i] = threading.Thread(target=is_on, args=(temp_ip,))
        threads[i].start()
    animate()    
    choose_ip(found_ips)
    
def extract_messages(message_and_sign):
    global queue
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
    queue = message_and_sign
    return (message, sign_message)

    


def get_message(skt):
    if queue:
        message = queue
    else:
        message = skt.recv(socket_message_size)
    if not message:
        disconnect()
        return ''
    # skt.send(randomString())
    message, sign_message = extract_messages(message)
    time.sleep(0.1)
    if not crypt_keys.check(sign_message, message, public_server):
        print2("warn: got message but can't verify it came from server!")
        return 1
    message = crypt_keys.decrypt(message, private_key)
    try:
        message = message.decode()
    except:
        pass
    return message

def send_message(message, skt, public_server, private_key):
    message = crypt_keys.encrypt(message, public_server)
    sign_message = crypt_keys.sign(message, private_key)
    message = message_with_len(message) 
    sign_message = message_with_len(sign_message)
    skt.send(message + sign_message)
    # nothing = skt.recv(socket_message_size)
    #time.sleep(0.1)

def disconnect():
    global connect
    if connect:
        print2("server disconnect...")
        connect = False
        print2("bye!")
        skt.close()

def randomString(stringLength=256):
    letters = string.ascii_lowercase
    return (''.join(random.choice(letters) for i in range(stringLength))).encode()

def login(skt, public_server, private_key):
    global connect
    logged_in = False
    while not logged_in:
        message = get_message(skt)
        time.sleep(0.5)
        if message == '':
            disconnect()
            return None
        elif message == 1:
            continue
        # skt.send(randomString())
        print2(message[:-1])
        end_of_message = int(message[-1])
        if end_of_message == 0:
            username = input("username: ") + 'q'
            send_message(username, skt, public_server, private_key)
        elif end_of_message == 1:
            password = input("password: ") + 'q'
            send_message(password, skt, public_server, private_key)
        elif end_of_message == 2:
            logged_in = True
    
def handle_user_message(message, skt):
    end_of_message = "q"
    command = ""
    if len(message) >= 1:
        if message[0] == "!":
            end_of_message = "c"
            message = message[1:]
            command = message
            message += end_of_message
            send_message(message, skt, public_server, private_key)
            if command != "":
                handle_commands(command)

def check_code(code, public_server):
    print("you got code %s from server, please check with the server you got the same code as he sent" % code.decode())
    if input("do you got the same code as server? (n for no, anything else for yes): ").lower() == 'n' or not crypt_keys.verify_code(code, public_server):
        print("probably someone listen to you, please check it and try again")
        disconnect()
        return False
    return True
    

# def get_message_from_user(skt):
#     global user_message
#     user_message = "<you> "
#     print("\r                                        \r", end="")
#     print2(user_message, end="")
#     a = getch.getch()
#     if a ==  '\x7f':
#         if len(user_message) > 6:
#             user_message = user_message[:-1]
#     else:
#         if a != '\x1b':
#             user_message += a
#     print2("\r" + (" " * (len(user_message) + 10)), end="\r")
#     print2(user_message, end="")
#     if a == "\n":
#         handle_user_message(user_message[6:], skt)
#         user_message = "<you> "
#         print2(user_message, end="")

# def get_message_from_server(skt):
#     while connect:
#         message = get_message(skt)
#         if message == '':
#             disconnect()
#             return None
#         elif message == 1:
#             continue
#         print2("\r" + (" " * ( len(user_message) + 10)), end=message) # clean user message and prinr message from server
#         print2(user_message, end="") # return the user message back to the screen




IP = input("inser the server ip (or nothing for search in your network): ")
PORT = -1
while PORT < 0 or PORT > 65535:
    try:
        PORT = input("insert the port number: (deafult 5555): ")
        if PORT == "":
            PORT = 5555
        else:
            PORT = int(PORT)
        if PORT < 0:
            print2("too low! range is 0 to 65535 ")
    except:
        print2("illigal choise! try again...")
        PORT = -1
    if PORT > 65535:
        print2("too high! range is 0 to 65535")
if IP == '':
    search_on_network()
private_key, public_key = crypt_keys.get_keys()
str_public = crypt_keys.public_to_str(public_key)

skt = socket.socket()
skt.connect((IP, PORT))

inputs = [skt, sys.stdin]
connect = True

print2("get server public key")
message = skt.recv(socket_message_size)
public_server = crypt_keys.str_to_public(message[6:])
print2("key received from server")
check_code(message[:6], public_server)
print2("send your public key and code to server")
code = crypt_keys.generate_code(public_key)
skt.send(code + str_public)
print2("key is sent to the server\n\n")
print2("send code %s to server, please verify the server got the same code" % code.decode())
# send_message(input("enter your name: "), skt, public_server, private_key)
# message = get_message(skt)
# print(message[:-1])
# if message[-1] == 'n':
#     connect = False


login(skt, public_server, private_key)

print2("<you> ", end="")
while True and connect:
    read, write, error = select.select(inputs, [], [])
    message = ""
    for inp in read:
        if inp == skt:
            message = get_message(inp)
            if message == '':
                disconnect()
                break
            elif message == 1:
                continue
            else:
                print2("\r" + (" " * 100) + "\r"  + message)
                print2("<you> ", end="")    
            
        else:
            message = sys.stdin.readline().rstrip()
            end_of_message = "q"
            command = ""
            start_of_message = "<you> "
            if len(message) >= 1:
                if message[0] == "!":
                    start_of_message = "<command> "
                    end_of_message = "c"
                    message = message[1:]
                    command = message
            print2("\033[1A\033[K" + start_of_message + message)
            message += end_of_message
            send_message(message, skt, public_server, private_key)
            if command != "":
                handle_commands(command)
            print2("<you> ", end="")
            
            
            # get_message_from_user(skt)    # if work than need only this to get message from user!


# user_thread = threading.Thread(target=get_message_from_user, args=(skt,))
# server_thread = threading.Thread(target=get_message_from_server, args=(skt,))
# user_thread.start()
# server_thread.start()
