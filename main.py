import random
import socketserver
import http.server
import http.cookies
import json
import base64
import sys
import os
import time

from fido2.client import ClientData
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import U2FFido2Server
from fido2.ctap2 import AttestationObject, AttestedCredentialData, AuthenticatorData
from fido2 import cbor

TOKEN_LIFETIME = 60 * 60 * 24
PORT = 8000
FORM = """
<body>
<script>

function atobarray(sBase64) {
    var sBinaryString = atob(sBase64), aBinaryView = new Uint8Array(sBinaryString.length);
    Array.prototype.forEach.call(aBinaryView, function (el, idx, arr) { arr[idx] = sBinaryString.charCodeAt(idx); });
    return aBinaryView;
}

function barraytoa(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

async function configure() {
    try {
        let data = await fetch('/auth/get_challenge_for_new_key', { method: 'POST' });
        let json = await data.json()
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.user.id = atobarray(json.publicKey.user.id)
        let cred = await navigator.credentials.create(json)
        window.command.innerHTML = 'On your server, to save this key please run:<br /><pre>python3 main.py save-client ' + window.location.host + ' ' + barraytoa(cred.response.clientDataJSON) + ' ' + barraytoa(cred.response.attestationObject) + '</pre>'
    } catch (e) {
        console.log(e)
    }
}

(async function init() {
    try {
        let data = await fetch('/auth/get_challenge_for_existing_key', { method: 'POST' });
        let json = await data.json()
        if (json.publicKey !== undefined) {
            json.publicKey.challenge = atobarray(json.publicKey.challenge)
            json.publicKey.allowCredentials[0].id = atobarray(json.publicKey.allowCredentials[0].id)
            let result = await navigator.credentials.get(json)
            await fetch('/auth/complete_challenge_for_existing_key', { method: 'POST', body: JSON.stringify({
              id: barraytoa(result.rawId),
              authenticatorData: barraytoa(result.response.authenticatorData),
              clientDataJSON: barraytoa(result.response.clientDataJSON),
              signature: barraytoa(result.response.signature)
            }), headers:{ 'Content-Type': 'application/json' }})
            window.location.href = "/"
        }
        if (json.error == 'not_configured') {
            configure();
        }
    } catch(e) {
        window.configure.style.display = '';
    }
})()
</script>
<div id="command"></div>
</body>
"""

class TokenManager(object):
    """Who needs a database when you can just store everything in memory?"""

    def __init__(self):
        self.tokens = {}
        self.random = random.SystemRandom()

    def generate(self):
        t = '%064x' % self.random.getrandbits(8*32)
        self.tokens[t] = time.time()
        return t

    def is_valid(self, t):
        try:
            return time.time() - self.tokens.get(t, 0) < TOKEN_LIFETIME
        except Exception:
            return False

    def invalidate(self, t):
        if t in self.tokens:
            del self.tokens[t]

CHALLENGE = {}
TOKEN_MANAGER = TokenManager()

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/auth/check':
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie and TOKEN_MANAGER.is_valid(cookie['token'].value):
                self.send_response(200)
                self.end_headers()
                return

            self.send_response(401)
            self.end_headers()
            return

        if self.path == "/auth/login":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        if self.path == '/auth/logout':
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie:
                TOKEN_MANAGER.invalidate(cookie['token'].value)

            # This just replaces the token with garbage
            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie["token"] = '***'
            cookie["token"]["path"] = '/'
            cookie["token"]["secure"] = True
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.send_header('Location', '/')
            self.end_headers()

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        origin = self.headers.get('Origin')
        host = origin[len('https://'):]

        rp = PublicKeyCredentialRpEntity(host, 'NGINX Auth Server')
        server = U2FFido2Server(origin, rp)

        if self.path == "/auth/get_challenge_for_new_key":
            registration_data, state = server.register_begin({ 'id': b'default', 'name': "Default user", 'displayName': "Default user" })
            registration_data["publicKey"]["challenge"] = str(base64.b64encode(registration_data["publicKey"]["challenge"]), 'utf-8')
            registration_data["publicKey"]["user"]["id"] = str(base64.b64encode(registration_data["publicKey"]["user"]["id"]), 'utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Save this challenge to a file so you can kill the host to add the lient via CLI
            with open('.lastchallenge', 'w') as f:
                f.write(json.dumps(state))
            self.wfile.write(bytes(json.dumps(registration_data), 'UTF-8'))
            return

        if not os.path.exists('.credentials'):
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'error': 'not_configured'}), 'UTF-8'))
            return

        creds = []
        with open('.credentials', 'rb') as f:
            cred, _ = AttestedCredentialData.unpack_from(f.read())
            creds.append(cred)

        if self.path == "/auth/get_challenge_for_existing_key":
            auth_data, state = server.authenticate_begin(creds)
            auth_data["publicKey"]["challenge"] = str(base64.b64encode(auth_data["publicKey"]["challenge"]), 'utf-8')
            auth_data["publicKey"]["allowCredentials"][0]["id"] = str(base64.b64encode(auth_data["publicKey"]["allowCredentials"][0]["id"]), 'utf-8')

            CHALLENGE.update(state)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(auth_data), 'UTF-8'))

        if self.path == "/auth/complete_challenge_for_existing_key":
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length'))))

            credential_id = base64.b64decode(data['id'])
            client_data = ClientData(base64.b64decode(data['clientDataJSON']))
            auth_data = AuthenticatorData(base64.b64decode(data['authenticatorData']))
            signature = base64.b64decode(data['signature'])

            with open('.lastchallenge') as f:
                server.authenticate_complete(
                    CHALLENGE,
                    creds,
                    credential_id,
                    client_data,
                    auth_data,
                    signature
                )

            cookie = http.cookies.SimpleCookie()
            cookie["token"] = TOKEN_MANAGER.generate()
            cookie["token"]["path"] = "/"
            cookie["token"]["secure"] = True

            self.send_response(200)
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'status': 'ok'}), 'UTF-8'))

if len(sys.argv) > 1 and sys.argv[1] == "save-client":
    host = sys.argv[2]
    client_data = ClientData(base64.b64decode(sys.argv[3]))
    attestation_object = AttestationObject(base64.b64decode(sys.argv[4]))

    rp = PublicKeyCredentialRpEntity(host, 'NGINX Auth Server')
    server = U2FFido2Server('https://' + host, rp)

    with open('.lastchallenge') as f:
        auth_data = server.register_complete(json.loads(f.read()), client_data, attestation_object)
        with open('.credentials', 'wb') as f:
            f.write(auth_data.credential_data)

    print("Credentials saved successfully")

else:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", PORT), AuthHandler)
    try:
        print("serving at port", PORT)
        httpd.serve_forever()
    finally:
        httpd.server_close()
