FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl gnupg lsb-release debconf-utils

RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections

RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
    | tee /etc/apt/sources.list.d/zeek.list

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg

RUN apt-get update && apt-get install -y zeek python3 python3-pip

WORKDIR /app

COPY backend /app/backend

RUN pip3 install -r /app/backend/requirements.txt

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}"]