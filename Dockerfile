FROM python:3.6.9-alpine3.10

LABEL maintainer="Rhino Assessment Team <pacu@rhinosecuritylabs.com>"
LABEL pacu.version="1.0.0"

# Install Pacu
WORKDIR /usr/src/pacu/
COPY ./requirements.txt ./
RUN pip install -r requirements.txt
COPY ./ ./

ENTRYPOINT [ "python3" ]
CMD ["pacu.py"]
