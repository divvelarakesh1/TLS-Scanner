FROM python:3.9-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    openssl \
    curl \
    git \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- THE FIX: NUCLEAR OVERRIDE ---
# Instead of editing the system file, we create a new 'unsafe' config
# that explicitly allows ALL ciphers and OLD protocols.
RUN echo 'openssl_conf = default_conf' > /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ default_conf ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'ssl_conf = ssl_sect' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ ssl_sect ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'system_default = system_default_sect' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ system_default_sect ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'MinProtocol = TLSv1' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'CipherString = ALL:@SECLEVEL=0' >> /etc/ssl/openssl-unsafe.cnf

# FORCE OpenSSL to use our custom unsafe config globally
ENV OPENSSL_CONF=/etc/ssl/openssl-unsafe.cnf

COPY . /app
RUN chown -R scanner:scanner /app

USER scanner
CMD ["python3", "main.py"]
