#!/usr/bin/python3

import users
import crypt_keys
import socket
import _thread as thread
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
    users.exit()
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


def get_ip():
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]
    except:
        return '0.0.0.0'


IP = get_ip()
PORT = 5555
clients = []
clients_keys = {}
clients_address = {}
private_key = {}
public_key = {}
commands = ["chkeys", "chname", "chtype", "adduser", "mute", "unmute", "kick", "users", "ban", "unban", "help"]
blacklist = []
client_users = {}
client_queue = {}
socket_message_size = 1030
users_muted = {}
writing = False
original_input = input
original_print = print
client_ip = {}
help = {
"chkeys": "!chkeys",
"chname": "!chname [new name]",
"chtype": "!chtype [username] [new type]",
"adduser": "!adduser [username] [password] [(optional) type]",
"mute": "!mute [username]",
"unmute": "!unmute [username]",
"kick": "!kick [username]",
"users": "!users [(optional flag) --ip] [(optional) username]",
"ban": "!ban [ip]",
"unban": "!unban [ip]",
"help": "!help [(optional) command]"
}
skt = None


def input(message):
    global writing
    while writing:
        time.sleep(1)
    writing = True
    result = original_input(message)
    writing = False
    return result

def print(message, end="\n", you=True):
    while writing:
        time.sleep(1)
    if you:
        message = "\r     \r" + message + "\n<you> "
        end=""
    original_print(message, end=end)
    sys.stdout.flush()

def get_conn_by_username(username):
    for c,name in client_users.items():
        if name == username:
            return True, c
    return False, ""


def send_message_to_user(username, message):
    exist, user_conn = get_conn_by_username(username)
    if exist:
        send_message(user_conn, message)

def check_ip(ip):
    try:
        ip = [int(i) for i in ip.split(".") if 0 <= int(i) <= 255]
    except ValueError:
        return False
    return len(ip) == 4



def handle_command(message, conn):
    global client_users
    user = client_users[conn]
    arr = []
    for m in message.replace("\t", " ").split(" "):
        if m != '':
            arr.append(m)
    message = arr
    command = message[0]
    params = message[1:]
    paramsnum = len(params)
    if command not in commands:
        send_message(conn, "invalid command! type '!help'")
        return True
    if command == "help":
        message = "invalid usage! type '!help help'"
        if paramsnum == 0:
            message = "\n".join(commands)
        elif paramsnum == 1:
            if params[0] in help:
                message = help[params[0]]
            else:
                message = "command '%s' is not defined" % params[0]
        send_message(conn, message)
    elif command == "chkeys":
        temp_message = conn.recv(socket_message_size * 10) 
        if temp_message:
                print("get public key from %s" % client_ip[conn])
                temp_message = temp_message
                length = int(temp_message.split(b" ")[0])
                temp_message = b" ".join(temp_message.split(b" ")[1:])
                signed = temp_message[:length]
                tmp_key = temp_message[length:]
                if crypt_keys.check(signed, tmp_key, clients_keys[conn]):
                    clients_keys[conn] = crypt_keys.str_to_public(tmp_key)
                else:
                    remove(conn, "error while trying to change key")
                return True
        else:
            return False
    elif command == "chname":
        if paramsnum != 2:
            send_message(conn, "invalid usage! type '!help chname'")
            return True
        old_username = params[0]
        new_username = params[1]
        success, message, username = users.change_name(user, old_username, new_username)
        send_message(conn, message)
        exist, tmp = get_conn_by_username(old_username)
        if exist:
            client_users[tmp] = username
            if success:
                send_message_to_user(username, "%s change your name to %s" % (user, username))
    elif command == "chtype":
        if paramsnum != 2:
            send_message(conn, "invalid usage! type '!help chtype'")
        username = params[0]
        new_type = params[1]
        success, message = users.change_type(user, username, new_type)
        send_message(conn, message)
        exist, conn_of_user = get_conn_by_username(username)
        if exist:
            send_message(conn_of_user, "%s change your type to %s" % (user, new_type))
            if success:
                send_message_to_user(username, "%s change your type to %s" % (client_users[conn], new_type))
    elif command == "adduser":
        if paramsnum == 2:
            params[2] = 'user'
            paramsnum += 1
        if paramsnum != 3:
            send_message(conn, "invalid usage! type '!help adduser'")
            return True
        username = params[0]
        password = params[1]
        usertype = params[2]
        message = users.create_user(user, username, password, usertype)
        send_message(conn, message)
    elif command == "mute":
        if paramsnum != 1:
            send_message(conn, "invalid usage! type '!help mute'")
            return True
        username = params[0]
        success, message = users.mute(user, username)
        if success:
            users_muted[username] = True
            send_message_to_user(username, "%s has muted you" % user)
        send_message(conn, message)
    elif command == "unmute":
        username = params[0]
        success, message = users.unmute(user, username)
        if success:
            users_muted[username] = False
            send_message_to_user(username, "%s has unmuted you" % user)
        send_message(conn, message)
    elif command == "kick":
        username = params[0]
        success, message = users.kick(user, username)
        send_message(conn, message)
        if success:
            reason =  "%s kicked %s" % (user, username)
            exist, c = get_conn_by_username(username)
            if exist:
                send_message_to_user(username, "%s has kicked you" % user)
                remove(c, reason , reason)
    elif command == "users":
        if paramsnum == 0:
            message = ""
            for c in client_users:
                username = client_users[c]
                message += "[%s] %s\n" % (users.users[username]['type'], username)
            send_message(conn, message)
        elif paramsnum == 1:
            if params[0] == "--ip":
                if not users.is_admin(client_users[conn]):
                    send_message(conn, "permission denied! only admin can use the --ip option")
                    return True
                message = ""
                for c in client_users:
                    username = client_users[c]
                    message += "[%s] %s : %s\n" % (users.users[username]['type'],  username,  client_ip[c])
                send_message(conn, message)
            else:
                exist, c = get_conn_by_username(params[0])
                if exist:
                    send_message(conn, "[%s] %s" % (users.users[params[0]]['type'], params[0]))
                else:
                    message = "invavild usage! type '!help users'"
                    if params[0][0] != "-":
                        if not users.user_exist(params[0]):
                            message = "user %s does not exsit!" % params[0]
                        else:
                            message = "user %s is not connect to server" % params[0]
                    send_message(conn, message)
                    return True
        elif paramsnum == 2:
            message = "invalid usage! type '!help users'"
            try:
                index = params.index("--ip")
            except ValueError:
                send_message(conn, message)
                return True
            if not users.is_admin(user):
                send_message(conn, "permission denied! only admin can use the --ip option")
                return True
            username = params[1 - index]
            exist, c = get_conn_by_username(username)
            if not exist:
                if username[0] != "-":
                    if not users.user_exist(username):
                        message = "user %s does not exsit!" % username
                    else:
                        message = "user %s is not connect to server" % username
                send_message(conn, message)
                return True
            send_message(conn, "[%s] %s : %s" % (users.users[username]['type'], username, client_ip[c]))
        else:
            send_message(conn, "invalid usage! type '!help users'")
    elif command == "ban":
        if not users.is_admin(user):
            send_message(conn, "permission denied! only admin can ban")
            return True
        ip = params[0]
        message = "invalid usage! type '!help ban'"
        if paramsnum == 1:
            if check_ip(ip):
                if users.is_admin(user):
                    blacklist.append(ip)
                    message = "ip '%s' banned successfully" % ip
            else:
                message  = "invalid ip '%s'" % ip
        send_message(conn, message)
    elif command == "unban":
        if not users.is_admin(user):
            send_message(conn, "permission denied! only admin can unban")
            return True
        ip = params[0]
        message = "invalid usage! type '!help ban'"
        if paramsnum == 1:
            if check_ip(ip):
                if ip in blacklist:
                    blacklist.remove(ip)
                    message = "ip '%s' unbanned successfully" % ip
                else:
                    message = "ip '%s' is not banned!" % ip
            else:
                message = "invalid ip '%s'" % ip
        send_message(conn, message)
    return True



def sign_up(conn, addr):
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


def message_with_len(message):
    try:
        message = message.encode()
    except:
        pass
    str_len = str(len(message))
    return ("0" * (3 - len(str_len))).encode() + str_len.encode() + message


def extract_messages(message_and_sign, conn):
    global client_queue
    try:
        message_and_sign = message_and_sign.encode()
    except:
        pass
    tmp_len = int(message_and_sign[:3]) + 3
    message = message_and_sign[3:tmp_len]
    message_and_sign = message_and_sign[tmp_len:]
    tmp_sign_len = int(message_and_sign[:3]) + 3
    sign_message = message_and_sign[3:tmp_sign_len]
    message_and_sign = message_and_sign[tmp_sign_len:]
    client_queue[conn] = message_and_sign
    return (message, sign_message)

def login(conn, addr):
    global client_users
    logged = False
    message = ""
    while not logged:
        print("get username from %s" % addr[0])
        send_message(conn, "%sinsert username (or 'sign up' for sign up) 0" % message) # extension 0 tells the client to insert a username
        username = get_message(conn)
        #time.sleep(2)
        if not username:
            return False
        print("username '%s' recived from %s" % (username[:-1], addr[0]))
        username = username[:-1]
        if username == 'sign up':
            print("%s sign up now..." % addr[0])
            return sign_up(conn, addr)
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
            message, sign_message = extract_messages(message, conn)
            # conn.send(randomString())
            time.sleep(0.5)
            if crypt_keys.check(sign_message, message, clients_keys[conn]):
                return crypt_keys.decrypt(message, private_key[conn]).decode()
            else:
                warn = "<server> A message was sent from this address that could not be verified! Note that someone may be trying to send messages on your behalf 3"
                send_message(conn, warn)
        else:
            reason = ""
            if conn in client_users:
                reason = "%s disconnected" % client_users[conn]
            remove(conn, clients_address[conn] + " disconnected", reason)
            return ''

def handle_client(conn, addr):
    global private_key, public_key
    clients_address[conn] = addr[0] + ":" + str(addr[1])
    private_key[conn], public_key[conn] = crypt_keys.get_keys()
    client_queue[conn] = ""
    client_ip[conn] = addr[0]
    code = crypt_keys.generate_code(public_key[conn])
    if addr[0] in blacklist:
        conn.send(b'you are ban from this serverq')
        remove(conn, "banned ip '%s' tried to connect and blocked" % addr[0])
        return
    else:
        conn.send(b'welcome to my message server\n\ne')
    print("send public key  and code to %s:%d" % (addr[0], addr[1]))
    conn.send(code + crypt_keys.public_to_str(public_key[conn]))
    print("key is sent")
    print("send to the client code: %s, please check with the clients he got the same code." % code.decode())
    temp_message = conn.recv(socket_message_size)
    if temp_message:
        print("get public key from %s:%d" % (addr[0], addr[1]))
        clients_keys[conn] = crypt_keys.str_to_public(temp_message)
    else:
        reason = ""
        if conn in client_users:
            reason = "%s disconnected" % client_users[conn]
        remove(conn, addr[0] + " disconnected", reason)
        return None
    print("key recived")
    # name = get_message(conn)
    # accept = input("%s try to connect to server in name '%s', do aprove? ('y' for yes and everythingelse for no): " %  (clients_address[conn], name))
    # if accept.lower() != 'y':
    #     send_message(conn, 'server refuse to connected! n')
    #     remove(conn, 'you rejected the connection of addres %s' % clients_address[conn], "") # extension n to say to the client that connection refused
    #     return None
    # send_message(conn, 'connected to server y') # extension y to say to the client that connection accepted
    if not login(conn, addr):
        return None
    name = "<" + client_users[conn] + "> "
    send_message(conn, "welcome to my chat room :)\n\n")
    send_to_everybody("%s joined" % client_users[conn], conn)
    while  True and conn in clients:
        message = get_message(conn)
        if message:
            if message[-1] == "c":
                message = message[:-1]
                print("recive command: " + name + message)
                if not handle_command(message, conn):
                    reason = ""
                    if conn in client_users:
                        reason = "%s disconnected" % client_users[conn]
                    remove(conn, addr[0] + " disconnected", reason)
                    return None
            else:
                message = name + message[:-1]
                print(message)
                send_to_everybody(message, conn)
        elif message == '':
            return None


def send_message(conn, message):
    message = crypt_keys.encrypt(message, clients_keys[conn])
    sign_message = crypt_keys.sign(message, private_key[conn])
    message = message_with_len(message)
    sign_message = message_with_len(sign_message)
    conn.send(message + sign_message)
    # nothing = conn.recv(socket_message_size)
    time.sleep(0.1)

def remove(conn, message="", reason=""):
    global clients, clients_keys, client_users
    if not message:
        message = "%s disconnected" % clients_address[conn]
    print(message)
    conn.close()
    if conn in clients:
        clients.remove(conn)
    if conn in clients_keys:
        clients_keys.pop(conn)
    if conn in client_users:
        users.logout(client_users[conn])
        client_users.pop(conn)
        send_to_everybody(reason, None)

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
                remove(c, "error", "%s disconnected" % client_users[c])
def server_messages():
    inputs = [sys.stdin]
    while True:
        read, write, error = select.select(inputs, [], [])
        server_message = ""
        for inp in read:
            server_message = sys.stdin.readline().rstrip()
            print("\033[1A\033[K<you> %s" % server_message)
            server_message = "<server> " + server_message
            send_to_everybody(server_message, None)
    
def new_connection(conn,addr):
    try:
        handle_client(conn, addr)
    except (BrokenPipeError, ConnectionResetError):
        remove(conn)
        


def main():
    global skt
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    skt.bind((IP, PORT))
    skt.listen(100)

    print("server start, listen on %s:%d" % (IP, PORT))



    thread.start_new_thread(server_messages, ())

    while True:
        conn, addr = skt.accept()
        clients.append(conn)
        print(str(addr[0]) + " connected")
        thread.start_new_thread(new_connection, (conn, addr))

if __name__ == "__main__":
    main()
