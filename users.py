import json
import os
from hashlib import sha512 
import uuid
import base64
import re

# deafult user: username: admin, password: admin
users = {
    'admin': {
        'start_salt': '5RJpr-v3T2K4wudpCG4POw==',
        'end_salt': 'YAEmL_UiTX2hp_1aq6IUAA==',
        'password': '2e094648a2c3fc168a585361d082599cf5cb2a8dac2cdcafd0f02edbd1adcd28d1d5f11be982e339897e57c9d9f1a063217faeb3c7e67ced683e2bbade3875dd',
        'type': 'admin',
        'is_logged' : False
    }
}


try:
    with open("users_data.json") as file:
        users = json.load(file)
except:
    pass


types = ["user", "admin"]
file_name = "users_data.json"
invaild_names = ['guest', '', 'sign up', 'server']

def is_admin(username):
    return users[username]["type"] == "admin"


def get_users():
    global users
    if os.path.isfile(file_name):
        with open(file_name, "r") as file:
            users = json.load(file)
    elif os.path.isdir(file_name):
        raise("%s is directory, expect it to be file..." % (file_name))
    else:
        with open(file_name, "w") as file:
            file.write(json.dumps(users))
    return users

def has_special(word):
    special_char = False
    regexp = re.compile('[^0-9a-zA-Z]+')
    if regexp.search(word):
        special_char = True
    return special_char

def save():
    with open(file_name, "w") as file:
        json.dump(users, file, indent=2)

def create_user(creator_name, username, password, usertype="user"):
    # check whether the user has permissions to create users
    try:
        if not is_admin(creator_name):
            return False, "6"
    except:
        if creator_name != "sign up":
            return False, "4"
    if has_special(username):
        return False, "0"
    # check if this name already exists
    if username in users:
        return False, "1"
    if username in invaild_names:
        return False, "2"
    if usertype not in types:
        return False, "5"
    users[username] = {}
    start_salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    end_salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    users[username]["start_salt"] = start_salt.decode()
    users[username]["end_salt"] = end_salt.decode()
    salted_password = start_salt + password.encode() + end_salt
    hashed_password = sha512(salted_password)
    users[username]["password"] = hashed_password.hexdigest()
    users[username]["type"] = usertype
    users[username]["is_logged"] = False
    save()
    return True, "3"

def login(username, password):
    if username not in users:
        return False, "0"
    if users[username]["is_logged"]:
        return False, "1"
    user = users[username]
    salted_password = (user["start_salt"] + password + user["end_salt"]).encode()
    if user["password"] == sha512(salted_password).hexdigest():
        users[username]["is_logged"] = True
        return True, "3"
    return False, "0"

def logout(username):
    if username in users:
        users[username]["is_logged"] = False

def close():
    for user in users:
        logout(user)
    save()

def change_type(user, username, new_type):
    global users
    if not is_admin(user):
        # return False, "permission denied"
        return False, "1"
    if not user_exist(username):
        # return False, "user does not exist"
        return False, "2"
    if new_type not in types:
        # return False, "invaild type!"
        return False, "3"
    users[username]["type"] = new_type
    save()
    # return True, "user type changed successfully"
    return True, "4"


def change_name(user, old_username, new_username):
    if not is_admin(user):
        if user != old_username:
            return False, "1", old_username # "permission denied"
    if not user_exist(old_username):
        return False, "2", old_username # "user does not exist"
    if new_username in invaild_names:
        return False, "3", old_username # "can't change to that name!"
    users[new_username] = users.pop(old_username)
    save()
    return True, "4", new_username # "username changed successfully"


def mute(user, username):
    if not is_admin(user):
        # return False, "permission denied"
        return False, "1"
    if not user_exist(username):
        # return False, "user does not exist"
        return False, "2"
    if users[username]["is_logged"]:
        # return True, "user muted successfully!"
        return True, "3"
    # return False, "user is not connected"
    return False, "4"
    

def unmute(user, username):
    if not is_admin(user):
        # return False, "permission denied"
        return False, "0"
    if not user_exist(username):
        # return False, "user does not exist"
        return False, "1"
    if users[username]["is_logged"]:
        # return True, "user unmuted successfully" 
        return True, "2"
    # return False, "user is not connected"
    return False, "3"

def kick(user, username):
    if not is_admin(user):
        # return False, "permission denied"
        return False, "1"
    if not user_exist(username):
        # return False, "user does not exist"
        return False, "2"
    if users[username]["is_logged"]:
        logout(username)
        # return True, "user kicked successfully"
        return True, "3"
    # return False, "user is not connected"
    return False, "4"

def exit():
    for user in users:
        logout(user)
    save()

def user_exist(username):
    return username in users