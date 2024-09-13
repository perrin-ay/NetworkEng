FROM python:2.7.15-slim

MAINTAINER Arnab Chatterjee

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -yq --force-yes --assume-yes tshark

RUN apt-get update && apt-get install -qq -y --force-yes build-essential libpq-dev libffi-dev --no-install-recommends

RUN apt-get install -qq -y git vim iputils-ping

#RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -yq --force-yes --assume-yes --allow-change-held-packages wireshark

WORKDIR /

COPY . /

RUN pip install --trusted-host pypi.python.org -r /requirements.txt


# Make port 80 available to the world outside this container
#EXPOSE 8049

#CMD ["gunicorn", "--timeout", "60", "--workers","4", "--threads","4", "--bind" ,"0.0.0.0:8052", "wsgi:app"]
