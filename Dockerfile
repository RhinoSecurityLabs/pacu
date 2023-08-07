FROM python:3.9-alpine

LABEL maintainer="Rhino Assessment Team <pacu@rhinosecuritylabs.com>"
LABEL pacu.version="1.0.1"

RUN apk add --no-cache \
    aws-cli \
    zip

# Install Pacu
WORKDIR /usr/src/pacu/
COPY ./ ./
RUN pip install .

RUN echo 'AWS_EC2_METADATA_DISABLED=true' >> /etc/profile

ENTRYPOINT ["pacu"]
