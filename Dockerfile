FROM python:3.9-alpine3.12

LABEL maintainer="Rhino Assessment Team <pacu@rhinosecuritylabs.com>"
LABEL pacu.version="1.0.1"

RUN apk add --no-cache aws-cli

# Install Pacu
WORKDIR /usr/src/pacu/
COPY ./requirements.txt ./
RUN pip install -r requirements.txt
COPY ./ ./

RUN echo 'AWS_EC2_METADATA_DISABLED=true' >> /etc/profile

ENTRYPOINT [ "python3", "pacu.py" ]
