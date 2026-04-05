FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# install zeek
RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
    > /etc/apt/sources.list.d/zeek.list

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg

RUN apt update && apt install -y zeek

ENV PATH="/opt/zeek/bin:${PATH}"

WORKDIR /app

COPY backend/ .

RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]