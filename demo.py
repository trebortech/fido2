'''
users DB
    userid      : unique userid
    username    : Provided by user
    pinhash     : Hash of PIN for user
    pinrequired : Set to true if user needs to provide PIN to authenticate (Only used for U2F logins)


Credential file name format
    userid     : from DB
    keyid      : Provided by user after registration process

    userid_keyid.p

'''
from random import randint

import pickle
import sqlite3
import hashlib
import os

userdb = "users.db"
defaultpin = "123456".encode("utf-8")


def db_conn():
    conn = sqlite3.connect(userdb)
    conn.text_factory = str
    db = conn.cursor()

    try:
        db.execute('''CREATE TABLE users(
                    userid TEXT,
                    username TEXT,
                    pinhash TEXT,
                    pinrequired TEXT)''')
        conn.commit()
    except Exception as e:
        print('DB already exists')

    return conn


def get_userobj(username = None):

    userobj = {}
    userobj = db_check(username)
    
    if len(userobj) == 0:
        # Create user
        userid = str(randint(0, 9999999999))
        pinhash = hashlib.sha256(defaultpin).hexdigest()
        pinrequired = True
        db_update(userid, str(username), pinhash, pinrequired)
        userobj = db_check(username)

    # User exist or has been created
    # Get the registered credentials if they exist
    credentials = get_credentials(userobj['userid'])
    userobj['credentials'] = credentials
    userobj['lencreds'] = len(credentials)
    return userobj


def get_credentials(userid):
    credentials = []
    for credfile in os.listdir('./users'):
        if credfile.startswith(userid):
            # Get file content
            credfiles = pickle.load(open('./users/' + credfile, "rb"))
            credentials.append(credfiles)
    return credentials


def db_update(userid, username, pinhash, pinrequired):
    db = db_conn()
    db.cursor()
    userid = str(userid)
    username = str(username)
    pinhash = str(pinhash)
    pinrequired = str(pinrequired)
    try:
        db.execute("INSERT INTO users(userid, username, pinhash, pinrequired) VALUES (?,?,?,?)",
                        (userid, username, pinhash, pinrequired))
        db.commit()
    except Exception as e:
        print("Error on insert")
    return "User created"

def db_check(username):
    db = db_conn()
    db.cursor()
    try:
        users = db.execute("SELECT userid, username, pinhash, pinrequired FROM users where username = ?", (str(username),))
        user = users.fetchall()[0]
        userobj = {}
        userobj['userid'] = user[0]
        userobj['username'] = user[1]
        userobj['pinhash'] = user[2]
        userobj['pinrequired'] = user[3]
    except Exception as e:
        return ''
    return userobj