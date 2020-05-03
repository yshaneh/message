import json
import os
from Crypto.Hash import SHA512
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

def create_user(creator_name, username, password):
    # check whether the user has permissions to create users
    try:
        if not is_admin(creator_name):
            return (False, "permission denied")
    except:
        if creator_name != "sign up":
            return (False, "error occurred...")
    if has_special(username):
        return (False, "username can only include numbers and letters")
    # check if this name already exists
    if username in users:
        return (False, "username is already exists")
    if username in invaild_names:
        return (False, "can't creat user with that name!")
    users[username] = {}
    start_salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    end_salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    users[username]["start_salt"] = start_salt.decode()
    users[username]["end_salt"] = end_salt.decode()
    salted_password = start_salt + password.encode() + end_salt
    hashed_password = SHA512.new(salted_password)
    users[username]["password"] = hashed_password.hexdigest()
    users[username]["type"] = "user"
    users[username]["is_logged"] = False
    save()
    return (True, "user created successfully")

def login(username, password):
    if username not in users:
        return (False, "wrong username or password, please try again...3")
    if users[username]["is_logged"]:
        return (False, "user is already logged in0")
    user = users[username]
    salted_password = (user["start_salt"] + password + user["end_salt"]).encode()
    if user["password"] == SHA512.new(salted_password).hexdigest():
        users[username]["is_logged"] = True
        return (True, "you have successfully logged in as %s2" % username)
    return (False, "wrong username or password, please try again...0")

def logout(username):
    if username in users:
        users[username]["is_logged"] = False

def close():
    for user in users:
        logout(user)
    save()

def change_type(user, username, new_type):
    global users
    last_type = users[username]["type"]
    if not is_admin(user):
        return "permission denied"
    elif new_type not in types:
        return "invaild type!"
    elif new_type == last_type:
        return "the type of user '%s' is already %s" % (username, new_type)
    users[username]["type"] = new_type
    save()
    return "the type of user '%s' has been successfully changed from '%s' to '%s'" % (username, last_type, new_type)


def change_name(user, old_username, new_username):
    if not is_admin(user):
        if user != old_username:
            return ("permission denied", old_username)
    if new_username in invaild_names:
        return ("can't change to that name!", old_username)
    users[new_username] = users.pop(old_username)
    save()
    return ("username changed successfully", new_username)


def mute(user, username):
    if not is_admin(user):
        return (False, "permission denied")
    if users[username]["is_logged"]:
        return (True, username + " muted successfully!")
    return (False, "user is not connected")
    

def unmute(user, username):
    if not is_admin(user):
        return (False, "permission denied")
    if users[username]["is_logged"]:
        return (True, "%s unmuted successfully")
    return (False, "user is not connected")

def kick(user, username):
    if not is_admin(user):
        return (False, "permission denied")
    if users[username]["is_logged"]:
        return (True, "%s kicked successfully")
    return (False, "user is not connected")


    
