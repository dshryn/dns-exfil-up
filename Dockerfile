FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# deps
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    curl \
    gnupg2 \
    ca-certificates \
    lsb-release \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# add Zeek repo
RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
    > /etc/apt/sources.list.d/zeek.list

RUN curl -fsSL \
    https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor \
    -o /etc/apt/trusted.gpg.d/zeek.gpg

# zeek
RUN apt-get update && apt-get install -y zeek \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# force cache break
COPY backend /app/backend
RUN echo "build $(date)" > /build.txt

RUN pip3 install --no-cache-dir -r /app/backend/requirements.txt

EXPOSE 8080

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]