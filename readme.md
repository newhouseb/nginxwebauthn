# NGINX + WebAuthn for your small scale web applications

## What is this for?

If you run some small services on a public-facing server that you would like to protect (i.e. Jupyter of VS code-server) and have a Yubikey or similar, you can use this repository to add secure, public-key authentication to them **without modifying the original service itself**.

## How?

Set up NGINX to proxy your service, note that you will also need SSL because WebAuthn only works over HTTPS.  I highly recommend using Let's Encrypt + `certbot` so set up SSL:

```
server {
    server_name myserver.bennewhouse.com; # managed by Certbot

    # Redirect everything that begins with /auth to the authorization server
    location /auth {
        proxy_pass http://127.0.0.1:8000;
    }

    # auth location can only be used for internal requests
    location = /auth {
        internal;
    }

    # If the authorization server returns 401 Unauthorized, redirect to /auth/login
    error_page 401 = @error401;
    location @error401 {
        return 302 /auth/login?target=$uri; # pass along the URI so we can redirect back to it
    }

    root /var/www/html;
    index index.html;
    location / {
        auth_request /auth/check; # Ping /auth/check for every request, and if it returns 200 OK grant access
      
        # Here is where you would put other proxy_pass info to forward to Jupyter, etc. In this example I'm just serving raw HTML
    }

    listen [::]:443 ssl ; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/myserver.bennewhouse.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/myserver.bennewhouse.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
```

Reload NGINX with the aforementioned configuration. Next install the required depenencies (only one at the moment) and run main.py in a long-running fashion (either in `tmux`, `screen` or if you're fancy a systemd daemon)

```
pip3 install -r requirements.txt
python3 main.py
```

Browse to your site on a page that supports WebAuthn (most things other than Safari). Insert your security key when requested, and the page will tell you to run a command that looks like:

```
python3 main.py save-client myserver.bennewhouse.com *big long base64 string* *big long base64 string*
```

Run that from the same place you've checked out this code. You only need to do this once to authorize your key.

That's it! Navigating back to your website will now authenticate you using the key you just saved.

## Running it as a service

For production the authentication can be run as a `systemd` service. The script contains the necessary provisions to run it as a daemon in the background. The script assumes that it's run by user `webauthn` with home directory `/home/webauthn`. You also have to create the directory `/var/run/webauthn/` and give the user access to it.

An example `systemd` config-file is shown below:
```
[Unit]
Description=Webauthn Server

[Service]
ExecStart=/home/webauthn/miniconda3/bin/python /home/webauthn/main.py
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
User=webauthn

[Install]
WantedBy=default.target
```

## Limitations

- At the moment, we only store one set of credentials. It'd be nice to store multiple credentials, especially across different domains.
- This uses the built-in python3 server, which isn't designed for high-volume. You'd want to port this to a uwsgi setup if you wanted to productionize it. 

## FAQ

*Why do I need to run the `save-client` command?*

This seemed easier than setting up a potentially insecure password so that you could authorize your key. Instead it asserts that you have shell access by requiring that you run a command.
