FROM python:3.9-alpine

LABEL maintainer="Rhino Assessment Team <pacu@rhinosecuritylabs.com>"
LABEL pacu.version="1.6.0"

# Install necessary packages
RUN apk add --no-cache \
    python3 \
    py3-pip \
    zip \
    curl \
    unzip

# Install AWS CLI using pip
RUN pip3 install --upgrade pip \
    && pip3 install awscli

# Install Pacu
WORKDIR /usr/src/pacu/
COPY ./ ./
RUN pip install .

RUN echo 'AWS_EC2_METADATA_DISABLED=true' >> /etc/profile

ENTRYPOINT ["pacu"]

