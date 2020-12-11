# LOIPY: Legacy OpenID Connect Integration Proxy for yes®

An OpenID Connect Identity Provider (IDP) proxy which translates "traditional" OpenID Connect requests into requests to the yes® ecosystem, including the bank/account chooser interface.

**IMPORTANT:** This server is designed to be operated under the control and within the network of a yes® relying party. It is not designed to be made available to arbitrary relying parties over the web. 


**Prerequisites**
 - Python > 3.6
 - The server requires a redis instance to cache user data.
 - The server requires a key pair to sign ID tokens with (even if you don't need ID tokens). Create a key pair (and matching self-signed certificate) with `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 10096 -subj '/CN=LOIPY' -nodes`

**Configuration**

Please read the notes in [configuration.example.yml](./configuration.example.yml) carefully and modify the file accordingly. When done, rename the file to `configuration.yml` (will be searched in the working directory) or set the environment variable `LOIPY_CONFIG_FILE` to point to the configuration file.

**Running**

The application server is based on flask and therefore can be run with any wsgi-compliant web server, e.g., gunicorn. For development, the standalone flask server can be used:
```bash
FLASK_APP=loipy.wsgi flask run -p 3000
```

**Docker**

A [Dockerfile](./docker/Dockerfile) is provided to build a docker image:
```bash
cd docker
docker build -t loipy .
```
To run the docker container:
 - Make sure that a redis server is running, e.g. using `docker run redis`.
 - Make sure that the redis URL in the configuration file points to this 
   docker server, e.g., using the host's docker0 IP: `redis://172.17.0.1:6379/0`
 - Put the signing key (as above) and the configuration file in `./data`
 - Put the yes client keys into `./data/yes-client/` and configure the `redirect_uri` and `client_id` to match the values registered with yes®.
```
docker run -e LOIPY_CONFIG_FILE=/data/configuration.yml -v `pwd`/data:/data loipy
```
