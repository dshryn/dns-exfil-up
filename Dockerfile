FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/zeek/bin:${PATH}"

# Install system + python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    curl gnupg2 ca-certificates lsb-release

# Add Zeek repo
RUN echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" > /etc/apt/sources.list.d/zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg

# Install Zeek
RUN apt-get update && apt-get install -y zeek

WORKDIR /app
COPY backend /app/backend

RUN pip3 install --no-cache-dir -r /app/backend/requirements.txt

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]