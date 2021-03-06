#!/usr/bin/python3

import socket
import select
import sys
import signal
import crypt_keys
import time
import _thread
import threading
from datetime import datetime
import math




found_ips = []
threads = {}
checked = 0
connect = False
user_message = ""
queue = ""
socket_message_size = 103
writing = False
skt, public_server, private_key, public_key, str_public, IP, PORT = None, None, None, None, None, None, None
commands_queue = []

RESPONSES = {
    "adduser" :  ["username can only include numbers and letters", "username is already exists", "can't creat user with that name!", "user created successfully", "error occurred...", "Invaild type!", "permission denied", "invalid usage! type '!help adduser'"],
    "help" : ["invalid usage! type '!help help'", "command is not defined"],
    "chname" : ["invalid usage! type '!help chname'", "permission denied", "user does not exist", "can't change to that name!", "username changed successfully"],
    "chtype" : ["invalid usage! type '!help chtype'", "permission denied", "user does not exist", "invaild type!", "user type changed successfully"],
    "mute" : ["invalid usage! type '!help mute'", "permission denied", "user does not exist", "user muted successfully!", "user is not connected"],
    "unmute" : ["permission denied", "user does not exist", "user unmuted successfully", "user is not connected"],
    "kick" : ["invalid usage! type '!help kick'", "permission denied", "user does not exist", "user kicked successfully", "user is not connected"],
    "users" : ["permission denied! only admin can use the --ip option", "invavild usage! type '!help users'", "user does not exsit!", "user is not connect to server"],
    "ban" : ["permission denied! only admin can ban", "invalid usage! type '!help ban'", "ip banned successfully", "invalid ip!"],
    "unban" : ["permission denied! only admin can unban", "invalid usage! type '!help unban'", "ip unbanned successfully", "ip is not banned!", "invalid ip!"]
}



class IO:
    def read(self):
        raise Exception('not implemented')

    def write(self, msg):
        raise Exception('not implemented')

class Console(IO):
    def read(self, msg=''):
        return input(msg)

    def write(self, msg, end="\n"):
        print(msg, end=end)
        sys.stdout.flush()

    def choose_ip(self):
        global IP, PORT
        IP = self.read("inser the server ip (or nothing for search in your network): ")
        PORT = -1
        while PORT < 0 or PORT > 65535:
            try:
                PORT = console.read("insert the port number: (deafult 5555): ")
                if PORT == "":
                    PORT = 5555
                else:
                    PORT = int(PORT)
                if PORT < 0:
                    console.write("too low! range is 0 to 65535 ")
            except:
                console.write("illegal choice! try again...")
                PORT = -1
            if PORT > 65535:
                console.write("too high! range is 0 to 65535")
        if IP == '':
            search_on_network()

    def get_messages(self):
        global writing
        while connect:
            while writing:
                time.sleep(0.5)
            writing = True
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
            now = datetime.now()
            self.write("\x1b[{}C\x1b[1A\r%s\r%d:%s %s%s" % ((" " * 100), now.hour, "%d%d" % (math.floor(now.minute/10) , (now.minute % 10)), start_of_message, message))
            message += end_of_message
            send_message(message, skt, public_server, private_key)
            if command != "":
                handle_commands(command)
            time.sleep(0.5)
            self.write("<you> ", end="")
            writing = False

    def exec(self):
        _thread.start_new_thread(self.get_messages, ())
        inputs = [skt]
        while True and connect:
            read, write, error = select.select(inputs, [], [])
            message = ""
            for inp in read:
                message = get_message()
                if message == '':
                    disconnect()
                    break
                elif message == 1:
                    continue
                else:
                    now = datetime.now()
                    self.write("\r%s\r%d:%s %s" % ((" " * 100), now.hour, "%d%d" % (math.floor(now.minute/10) , (now.minute % 10)) ,message))
                    self.write("<you> ", end="")

def signal_handler(sig, frame):
    console.write('by!\n')
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

def handle_commands(message):
    global private_key, public_key, str_public, commands_queue
    command = message.split(" ")[0]
    commands_queue.append(command)
    if command == "chkeys":
        old_private = private_key
        console.write("\ngenerate new keys...")
        private_key, public_key = crypt_keys.get_keys()
        str_public = crypt_keys.public_to_str(public_key)
        console.write("keys generated")
        console.write("\n\n%s\n\n" % str_public.decode())
        console.write("send new public key to server...")
        signed = crypt_keys.sign(str_public, old_private)
        skt.send(b"%d %s%s" % (len(signed), signed, str_public))
        console.write("public key is sent to the server\n")

def print_response(message):
    console.write("\r%s\r%s\n<you> " % (" " * 500, get_response(message)), end="")

def get_response(message):
    try:
        message = int(message)
    except ValueError:
        return message
    if len(commands_queue) == 0:
        return "Error! commands queue is empty"
    command = commands_queue.pop(0)


    if command in RESPONSES:
        try:
            return RESPONSES[command][message]
        except:
            return "Error! got response '%s' to unknow command: '%s'" % (message, command)
    else:
        return "unknown command '%s'" % command

def message_with_len(message):
    try:
        message = message.encode()
    except:
        pass
    str_len = str(len(message)).encode()
    return b'%s%s %s' % (b'0' * (3 - len(str_len)), str_len, message)

def animate():
    while checked < len(threads):
        console.write("\rscaning network... %0.2f%s" % (checked * 100 / len(threads), "%"), end="")
        time.sleep(0.2)
    console.write("\rscaning network... %0.2f%s" % (checked * 100 / len(threads), "%"), end="\n\n")

def choose_ip(found_ips):
    global IP
    number_of_options = len(found_ips)
    if number_of_options == 0:
        console.write("There is no ip in your network that listens to port %d" % (PORT))
        IP = console.read("please insert the server ip: ")
        return None
    for i in range(len(found_ips)):
        console.write("%d: %s" % (i+1, found_ips[i]))
    console.write("\n\n")
    choice = -1
    while choice < 1 or choice > number_of_options:
        choice = console.read("choose ip of the above (enter the number of his place on the list): ")
        try:
            choice = int(choice)
            if choice < 1:
                console.write("illegal, number is too low!")
            elif choice > len(found_ips):
                console.write("illegal, number is too high!")
        except:
            console.write("illegal input! you need to insert number")
            choice = -1
    IP = found_ips[choice - 1]

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
    skt_try.settimeout(3)
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
    for i in range(1, 255):
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
    while not b' ' in message_and_sign:
        tmp = skt.recv(10)
        if not tmp:
            disconnect(conn, "error while trying to get message from server")
            return False
        message_and_sign += tmp
    splited = message_and_sign.split(b' ')
    try:
        tmp_len = int(splited)[0]
    except ValueError:
        disconnect("error while trying to get message from server")
    message_and_sign =  b' '.join(splited[1:])
    while len(message_and_sign) < tmp_len * 2:
        tmp = skt.recv(tmp_len)
    message = message_and_sign[:tmp_len]
    sign_message = message_and_sign[tmp_len:tmp_len*2]
    message_and_sign = message_and_sign[tmp_len*2:]
    queue = message_and_sign
    return (message, sign_message)

def get_message():
    if queue:
        message = queue
    else:
        message = skt.recv(socket_message_size)
    if not message:
        disconnect()
        return ''
    message, sign_message = extract_messages(message)
    if not message:
        return ''
    if not crypt_keys.check(sign_message, message, public_server):
        console.write("warn: got message but can't verify it came from server!")
        return 1
    message = crypt_keys.decrypt(message, private_key)
    try:
        message = message.decode()
    except:
        pass
    ext = "q"
    if len(message) > 0:
        ext = message[-1]
        message = message[:-1]
    if ext == "q":
        return message
    elif ext == "c":
        print_response(message)
        return get_message()
    else:
        raise Exception('weird exention: %s' % ext)


def send_message(message, skt, public_server, private_key):
    message = crypt_keys.encrypt(message, public_server)
    sign_message = crypt_keys.sign(message, private_key)
    message = message_with_len(message)
    sign_message = sign_message
    skt.send(b'%s%s' % (message, sign_message))

def disconnect(reason="server disconnect..."):
    global connect
    if connect:
        console.write(reason)
        connect = False
        console.write("bye!")
        skt.close()
    sys.exit(0)

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


def status():
    try:
        message = get_message()
        return int(message)
    except:
        return


def login(username, password):
    messages = ["wrong username or password, please try again...\n\n", "user is already logged in\n\n", "invalid loggin!", "you have successfully logged in as %s" % username]
    send_message("%s\n%sq" % (username, password), skt, public_server, private_key)
    message = status()
    if message == None:
        return False
    try:
        console.write(messages[message])
    except:
        pass
    return message == 3

def signup(username, password, confirm_password):
    messages = ["username can only include numbers and letters", "username is already exists", "can't creat user with that name!", "user created successfully"]
    if password != confirm_password:
        console.write("passwords does not match. try again...")
        return False
    send_message("%s\n%sq" % (username, password), skt, public_server, private_key)
    message = status()
    if message == None:
        return False
    console.write(messages[message])
    return message == 3

def check_code(code, public_server):
    console.write("you got code %s from server, please check with the server you got the same code as he sent" % code.decode())
    if console.read("do you got the same code as server? (n for no, anything else for yes): ").lower() == 'n' or not crypt_keys.verify_code(code, public_server):
        console.write("probably someone listen to you, please check it and try again")
        disconnect()
        return False
    return True

def connect():
    global  skt, connect, public_server, private_key, public_key, str_public
    private_key, public_key = crypt_keys.get_keys()
    str_public = crypt_keys.public_to_str(public_key)

    skt = socket.socket()
    skt.connect((IP, PORT))
    connect = True

    message = skt.recv(1024).decode()
    if not message:
        disconnect()
        return
    console.write(message[:-1])
    if message[-1] == "q":
        disconnect()
        return
    console.write("get server public key")
    message = skt.recv(socket_message_size)
    if not message:
        disconnect("error while trying to get public key from server")
        return
    while not b' ' in message:
        tmp = skt.recv(10)
        if tmp:
            message += tmp
        else:
            disconnect()
            return
    length = message.split(b' ')[0].decode()
    try:
        length = int(length)
    except ValueError:
        disconnect("error while trying to get public key from server")
        return
    message = b' '.join(message.split(b' ')[1:])
    while len(message) < length:
        tmp = skt.recv(socket_message_size)
        if tmp:
            message += tmp
        else:
            disconnect()
            return
    code_size=23
    public_server = crypt_keys.str_to_public(message[code_size:])
    if not public_server:
        console.write("server disconnected")
        return
    console.write("key received from server")
    check_code(message[:code_size], public_server)
    console.write("send your public key to server")
    skt.send(b'%d %s' % (len(str_public), str_public))
    console.write("key is sent to the server\n\n")

def identification():
    logged = False
    action = ""
    while action != "login" and action != "sign up":
        action = input("insert 'login' to login or 'sign up' to sign up: ")
    if action == "login":
        while not logged:
            logged = login(console.read("username: "), console.read("password: "))
    else:
        send_message("sign up", skt, public_server, private_key)
        get_message()
        while not logged:
            logged = signup(console.read("username: "), console.read("password: "), console.read("confirm password: "))
    console.write("<you> ", end="")

def main():
    console.choose_ip()
    connect()
    identification()
    console.exec()


if __name__ == "__main__":
    console = Console()
    try:
        main()
    except (ConnectionResetError, BrokenPipeError):
        disconnect()
        sys.exit(0)
