from json.decoder import JSONDecodeError
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
        window.command.innerHTML = 'On your server, to save this key please run:<br /><pre>python main.py save-client ' + window.location.host + ' ' + barraytoa(cred.response.clientDataJSON) + ' ' + barraytoa(cred.response.attestationObject) + '</pre>'
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
            for (let i = 0; i < json.publicKey.allowCredentials.length; i++) {
                json.publicKey.allowCredentials[i].id = atobarray(json.publicKey.allowCredentials[i].id)
            }
            try {
                var result = await navigator.credentials.get(json)
            } catch(e) {
                console.log('unknown key')
                await configure()
                return
            }
            await fetch('/auth/complete_challenge_for_existing_key', { method: 'POST', body: JSON.stringify({
              id: barraytoa(result.rawId),
              authenticatorData: barraytoa(result.response.authenticatorData),
              clientDataJSON: barraytoa(result.response.clientDataJSON),
              signature: barraytoa(result.response.signature)
            }), headers:{ 'Content-Type': 'application/json' }})
            let params = await new URLSearchParams(window.location.search)
            if (params.has('target')) {
                window.location.href = params.get('target')
            } else {
                window.location.href = "/"
            }
        }
        if (json.error == 'not_configured') {
            await configure()
        }
    } catch(e) {
        console.log(e)
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
            if '__Secure-Token' in cookie and TOKEN_MANAGER.is_valid(cookie['__Secure-Token'].value):
                self.send_response(200)
                self.end_headers()
                return

            self.send_response(401)
            self.end_headers()
            return

        if self.path[:11] == "/auth/login":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        if self.path == '/auth/logout':
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if '__Secure-Token' in cookie:
                TOKEN_MANAGER.invalidate(cookie['__Secure-Token'].value)

            # This just replaces the token with garbage
            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie["__Secure-Token"] = ''
            cookie["__Secure-Token"]["path"] = '/'
            cookie["__Secure-Token"]["secure"] = True
            cookie["__Secure-Token"]["max-age"] = 0 # remove the cookie ASAP
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
            # check whether credentials file is locked (can't be written)
            if os.access('.credentials', os.F_OK) and not os.access('.credentials', os.W_OK):
                self.send_response(403)
                self.end_headers()
                return

            registration_data, state = server.register_begin({ 'id': b'default', 'name': "Default user", 'displayName': "Default user" })
            registration_data["publicKey"]["challenge"] = str(base64.b64encode(registration_data["publicKey"]["challenge"]), 'utf-8')
            registration_data["publicKey"]["user"]["id"] = str(base64.b64encode(registration_data["publicKey"]["user"]["id"]), 'utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Save this challenge to a file so you can kill the host to add the client via CLI
            with open('.lastchallenge', 'w') as f:
                f.write(json.dumps(state))
            self.wfile.write(bytes(json.dumps(registration_data), 'UTF-8'))
            return

        creds = []
        try:
            with open('.credentials', 'r', encoding='utf8') as f:
                for cred_b64 in json.load(f):
                    cred, _ = AttestedCredentialData.unpack_from(base64.b64decode(cred_b64))
                    creds.append(cred)
        except:
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'error': 'not_configured'}), 'UTF-8'))
            return

        if self.path == "/auth/get_challenge_for_existing_key":
            auth_data, state = server.authenticate_begin(creds)
            auth_data["publicKey"]["challenge"] = str(base64.b64encode(auth_data["publicKey"]["challenge"]), 'utf-8')
            for i in range(len(auth_data["publicKey"]["allowCredentials"])):
                auth_data["publicKey"]["allowCredentials"][i]["id"] = base64.b64encode(auth_data["publicKey"]["allowCredentials"][i]["id"]).decode('utf8')

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

            server.authenticate_complete(
                CHALLENGE,
                creds,
                credential_id,
                client_data,
                auth_data,
                signature
            )

            cookie = http.cookies.SimpleCookie()
            cookie["__Secure-Token"] = TOKEN_MANAGER.generate()
            cookie["__Secure-Token"]["path"] = "/"
            cookie["__Secure-Token"]["secure"] = True
            cookie["__Secure-Token"]["httponly"] = True
            cookie["__Secure-Token"]["samesite"] = 'Strict'
            cookie["__Secure-Token"]["max-age"] = TOKEN_LIFETIME

            self.send_response(200)
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'status': 'ok'}), 'UTF-8'))

if __name__ == "__main__":

    def run_server():
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("", PORT), AuthHandler)
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    if len(sys.argv) > 1 and sys.argv[1] == "save-client":
        host = sys.argv[2]
        client_data = ClientData(base64.b64decode(sys.argv[3]))
        attestation_object = AttestationObject(base64.b64decode(sys.argv[4]))

        rp = PublicKeyCredentialRpEntity(host, 'NGINX Auth Server')
        server = U2FFido2Server('https://' + host, rp)

        with open('.lastchallenge') as f:
            auth_data = server.register_complete(json.loads(f.read()), client_data, attestation_object)
            cred = base64.b64encode(auth_data.credential_data).decode('utf8')
            with open('.credentials', 'a+', encoding='utf8') as f:
                f.seek(0)
                try:
                    creds = json.load(f)
                except JSONDecodeError:
                    creds = []
                    print("Created new credentials file")
                if cred not in creds:
                    creds.append(cred)
                    f.truncate(0)
                    json.dump(creds, f)
                    print("Credentials saved successfully")
                else:
                    print("Credentials already in database")

    elif len(sys.argv) == 2 and sys.argv[1] == '-d':
        # starts the server non-daemonized
        run_server()

    else:
        from daemon import DaemonContext
        from sys import stdout, stderr, exit
        from lockfile import FileLock
        from signal import SIGTERM, SIGTSTP

        def shutdown(signum, frame):
            exit(0)

        with DaemonContext(
                chroot_directory=None,
                working_directory='/home/webauthn',
                stdout=stdout,
                stderr=stderr,
                pidfile=FileLock('/var/run/webauthn/webauthn.pid'),
                signal_map={
                    SIGTERM: shutdown,
                    SIGTSTP: shutdown
                }):
            run_server()
