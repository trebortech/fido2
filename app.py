from __future__ import print_function, absolute_import, unicode_literals

from fido2.client import ClientData
from fido2.server import U2FFido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from flask import Flask, request, redirect, abort, render_template
from binascii import b2a_hex

import pickle
import demo
import os

app = Flask(__name__, static_url_path='')

app_id = {

}

rp = {
    'id': 'u2f.demo.lab',
    'name': 'U2F Demo Server'
}


fidoserver = U2FFido2Server(app_id, rp)
credentials = []
session = {}

@app.route('/')
def index():
    return render_template('/login.html')

@app.route('/api/user/check', methods=['POST','GET'])
def check_user():
    username = request.args['username']
    action = request.args['action']

    userobj = demo.get_userobj(username)
    
    session['userobj'] = userobj

    if userobj['lencreds'] == 0 or action == 'register':
        site = 'register.html'
        return render_template(site)
    else:    
        site = 'authenticate.html'
        return render_template(site)
    return  
 
@app.route('/api/register/begin', methods=['POST'])
def register_begin():
    userobj = session['userobj']
    registration_data, state = fidoserver.register_begin(
        {
            "id": userobj['userid'].encode(),
            "name": userobj['username'].encode(),
            "displayName": userobj['username'].encode(),
        },
        userobj['credentials'],
        user_verification='discouraged',
        authenticator_attachment='cross-platform',
    )
    session['state'] = state
    return cbor.encode(registration_data)

@app.route('/api/register/complete', methods=['POST'])
def register_complete():

    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data['attestationObject'])

    auth_data = fidoserver.register_complete(session['state'], client_data, att_obj)

    # Check if key has already been registered
    certificateid = att_obj.auth_data.credential_data.credential_id

    fileid = session['userobj']['userid'] + "_" + b2a_hex(certificateid).decode()

    pickle.dump(att_obj.auth_data.credential_data, open("./users/" + fileid + ".p", "wb"))

    return cbor.encode({'status': 'OK'})


@app.route('/api/authenticate/begin', methods=['POST'])
def autenticate_begin():

    #This will build the call to the authenticator
    credentials = session['userobj']['credentials']
    auth_data, state = fidoserver.authenticate_begin(credentials, user_verification='discouraged', challenge=b"f4c9f562cf57550be422c4db2ab3b6042ec9a517301885891dc1d0c9bba457ca",)
    session['challenge'] = state
    return cbor.encode(auth_data)


@app.route('/api/authenticate/complete', methods=['POST'])
def authenticate_complete():
    data = cbor.decode(request.get_data())
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']

    # If I wanted to check counter
    # auth_data.counter and compare to what is in db. make sure the number is greater.

    credentials = session['userobj']['credentials']
    fidoserver.authenticate_complete(
        session.pop('challenge'),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,)
    
    return cbor.encode({'status': 'OK'})

@app.route('/api/registerhmac/begin', methods=['POST'])
def registerhmac_begin():
    userobj = session['userobj']
    registration_data, state = fidoserver.register_begin(
        {
            "id": userobj['userid'].encode(),
            "name": userobj['username'].encode(),
            "displayName": userobj['username'].encode(),
        },
        userobj['credentials'],
        user_verification='discouraged',
        authenticator_attachment='cross-platform',
    )

    options = registration_data["publicKey"]
    options.extensions = {"hmacCreateSecret": True}
    session['state'] = state
    return cbor.encode(registration_data)

@app.route('/api/registerhmac/complete', methods=['POST'])
def registerhmac_complete():

    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data['attestationObject'])

    auth_data = fidoserver.register_complete(session['state'], client_data, att_obj)

    # Check if key has already been registered
    certificateid = att_obj.auth_data.credential_data.credential_id

    fileid = session['userobj']['userid'] + "_" + b2a_hex(certificateid).decode()

    pickle.dump(att_obj.auth_data.credential_data, open("./users/" + fileid + ".p", "wb"))
    return cbor.encode({'status': 'OK'})

@app.route('/api/hmac/begin', methods=['POST'])
def hmac_begin():

    salt = os.urandom(32)
    #This will build the call to the authenticator
    credentials = session['userobj']['credentials']
    auth_data, state = fidoserver.authenticate_begin(
        credentials,
        user_verification='preferred',
    )
    options = auth_data["publicKey"]
    options.extensions = {"hmacGetSecret": {"salt1": salt}}
    session['challenge'] = state
    return cbor.encode(auth_data)


@app.route('/api/hmac/complete', methods=['POST'])
def hmac_complete():
    data = cbor.decode(request.get_data())
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']

    import pdb;pdb.set_trace()
    # If I wanted to check counter
    # auth_data.counter and compare to what is in db. make sure the number is greater.

    credentials = session['userobj']['credentials']
    fidoserver.authenticate_complete(
        session.pop('challenge'),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,)
    
    return cbor.encode({'status': 'OK'})


@app.route('/success', methods=['POST', 'GET'])
def auth_user():
    userobj = session['userobj']
    site = 'success.html'
    return render_template(site)

if __name__ == '__main__':
    print(__doc__)
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc', debug=True)