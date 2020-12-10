# LOIPY: Legacy OpenID Connect Integration Proxy for yes®

An OpenID Connect Identity Provider (IDP) proxy which translates "traditional" OpenID Connect requests into requests to the yes® ecosystem, including the bank/account chooser interface.

**IMPORTANT:** This server is designed to be operated under the control and within the network of a yes® relying party. It is not designed to be made available to arbitrary relying parties over the web. 


**Prerequisites**
 - Python > 3.6
 - The server requires a redis instance to cache user data.
 - The server requires a key pair to sign ID tokens with (even if you don't need ID tokens). Create a key pair (and matching self-signed certificate) with `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 10096 -subj '/CN=LOIPY' -nodes`

**Configuration**

See [configuration.example.yml](./configuration.example.yml). Rename to `configuration.yml`.

**Running**

The application server is based on flask and therefore can be run with any wsgi-compliant web server, e.g., gunicorn. For development, the standalone flask server can be used:
```bash
FLASK_APP=loipy.wsgi flask run -p 3000
```


