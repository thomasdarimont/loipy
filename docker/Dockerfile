FROM tiangolo/uwsgi-nginx-flask:python3.8
RUN apt-get update && \
    apt-get install --no-install-recommends -y python3-cryptography python3-cffi python3-urllib3 ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip install git+https://github.com/yescom/loipy
COPY ./main.py /app/main.py