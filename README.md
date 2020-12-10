# LOIPY: Legacy OpenID Connect Integration Proxy for yes®

An OpenID Connect Identity Provider (IDP) proxy which translates "traditional" OpenID Connect requests into requests to the yes® ecosystem, including the bank/account chooser interface.

**IMPORTANT:** This server is designed to be operated under the control of a yes® relying party. It is not designed to be made available to arbitrary relying parties over the web. 

The application server is based on flask and therefore can be run with any wsgi-compliant web server, e.g., gunicorn. For development, the standalone flask server can be used:
```bash
FLASK_APP=loipy.wsgi flask run -p 3000
```

The server requires a redis instance to cache user data.

