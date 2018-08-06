from __future__ import print_function, absolute_import, unicode_literals

from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from flask import Flask, request, redirect, abort, render_template
from binascii import b2a_hex

import pickle
import demo

app = Flask(__name__, static_url_path='')

fidoserver  = Fido2Server('u2f.demo.lab')
rp = {
    'id': 'u2f.demo.lab',
    'name': 'U2F Demo Server'
}

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
 
@app.route('/api/register/begin', methods=['POST','GET'])
def register_begin():

    userobj = session['userobj']
    userreq = {
        'id': userobj['userid'],
        'name': userobj['username'],
        'displayName': userobj['username']
    }
    credentials = userobj['credentials']
    registration_data = fidoserver.register_begin(rp, userreq, credentials)
    session['challenge'] = registration_data['publicKey']['challenge']
    return cbor.dumps(registration_data)

@app.route('/api/register/complete', methods=['POST'])
def register_complete():

    data = cbor.loads(request.get_data())[0]
    client_data = ClientData(data['clientDataJSON'])
    att_obj = AttestationObject(data['attestationObject'])


    val = session['challenge']
    auth_data = fidoserver.register_complete(val, client_data, att_obj)

    # Check if key has already been registered

    certificateid = att_obj.auth_data.credential_data.credential_id

    fileid = session['userobj']['userid'] + "_" + b2a_hex(certificateid).decode()

    pickle.dump(att_obj.auth_data.credential_data, open("./users/" + fileid + ".p", "wb"))

    return cbor.dumps({'status': 'OK'})


@app.route('/api/authenticate/begin', methods=['POST'])
def autenticate_begin():

    credentials = session['userobj']['credentials']
    auth_data = fidoserver.authenticate_begin(rp['id'], credentials)
    session['challenge'] = auth_data['publicKey']['challenge']
    return cbor.dumps(auth_data)


@app.route('/api/authenticate/complete', methods=['POST'])
def authenticate_complete():
    data = cbor.loads(request.get_data())[0]
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']

    credentials = session['userobj']['credentials']
    fidoserver.authenticate_complete(credentials, credential_id,
                                 session.pop('challenge'), client_data,
                                 auth_data, signature)
    return cbor.dumps({'status': 'OK'})


@app.route('/success', methods=['POST', 'GET'])
def auth_user():
    userobj = session['userobj']
    site = 'success.html'
    return render_template(site)

if __name__ == '__main__':
    print(__doc__)
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc', debug=True)