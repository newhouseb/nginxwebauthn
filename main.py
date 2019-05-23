import random
import socketserver
import http.server
import json
import base64
import sys
import os

from fido2.client import ClientData
from fido2.server import U2FFido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AttestedCredentialData, AuthenticatorData
from fido2 import cbor

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
        let data = await fetch('/auth/setup', { method: 'POST' });
        let json = await data.json()
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.user.id = atobarray(json.publicKey.user.id)
        let cred = await navigator.credentials.create(json)
        window.command.innerHTML = 'python3 main.py save-client ' + window.location.host + ' ' + barraytoa(cred.response.clientDataJSON) + ' ' + barraytoa(cred.response.attestationObject)
    } catch (e) {
        console.log(e)
    }
}

(async function init() {
    let data = await fetch('/auth/begin', { method: 'POST' });
    let json = await data.json()
    if (json.publicKey !== undefined) {
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.allowCredentials[0].id = atobarray(json.publicKey.allowCredentials[0].id)
        let result = await navigator.credentials.get(json)
        await fetch('/auth/complete', { method: 'POST', body: JSON.stringify({
          id: barraytoa(result.rawId),
          authenticatorData: barraytoa(result.response.authenticatorData),
          clientDataJSON: barraytoa(result.response.clientDataJSON),
          signature: barraytoa(result.response.signature)
        }), headers:{ 'Content-Type': 'application/json' }})
        console.log(result)
    }

})()
</script>
<button onclick="configure()">Configure</button>
<div id="command"></div>
</body>
"""

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/auth":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

    def do_POST(self):
        origin = self.headers.get('Origin')
        host = origin[len('https://'):]

        rp = RelyingParty(host, 'NGINX Auth Server')
        server = U2FFido2Server(origin, rp)

        if self.path == "/auth/setup":
            registration_data, state = server.register_begin({ 'id': b'default', 'name': "Default user", 'displayName': "Default user" })
            registration_data["publicKey"]["challenge"] = str(base64.b64encode(registration_data["publicKey"]["challenge"]), 'utf-8')
            registration_data["publicKey"]["user"]["id"] = str(base64.b64encode(registration_data["publicKey"]["user"]["id"]), 'utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            with open('.lastchallenge', 'w') as f:
                f.write(json.dumps(state))
            self.wfile.write(bytes(json.dumps(registration_data), 'UTF-8'))
            return

        creds = []
        with open('.credentials', 'rb') as f:
            cred, _ = AttestedCredentialData.unpack_from(f.read())
            creds.append(cred)

        if self.path == "/auth/begin":
            auth_data, state = server.authenticate_begin(creds)
            auth_data["publicKey"]["challenge"] = str(base64.b64encode(auth_data["publicKey"]["challenge"]), 'utf-8')
            auth_data["publicKey"]["allowCredentials"][0]["id"] = str(base64.b64encode(auth_data["publicKey"]["allowCredentials"][0]["id"]), 'utf-8')

            with open('.lastchallenge', 'w') as f:
                f.write(json.dumps(state))

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(auth_data), 'UTF-8'))

        if self.path == "/auth/complete":
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length'))))

            credential_id = base64.b64decode(data['id'])
            client_data = ClientData(base64.b64decode(data['clientDataJSON']))
            auth_data = AuthenticatorData(base64.b64decode(data['authenticatorData']))
            signature = base64.b64decode(data['signature'])

            with open('.lastchallenge') as f:
                server.authenticate_complete(
                    json.loads(f.read()),
                    creds,
                    credential_id,
                    client_data,
                    auth_data,
                    signature
                )

            print("Auth ok!")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

if len(sys.argv) > 1 and sys.argv[1] == "save-client":
    host = sys.argv[2]
    client_data = ClientData(base64.b64decode(sys.argv[3]))
    attestation_object = AttestationObject(base64.b64decode(sys.argv[4]))

    rp = RelyingParty(host, 'NGINX Auth Server')
    server = U2FFido2Server('https://' + host, rp)

    with open('.lastchallenge') as f:
        auth_data = server.register_complete(json.loads(f.read()), client_data, attestation_object)
        with open('.credentials', 'wb') as f:
            f.write(auth_data.credential_data)

    print("Credentials save successfully")

else:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", PORT), AuthHandler)
    try:
        print("serving at port", PORT)
        httpd.serve_forever()
    finally:
        httpd.server_close()
