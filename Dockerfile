# 1. Use Python 3.9 on Debian 10 (Buster)
# We need Buster because it uses OpenSSL 1.1.1, which supports SSLv3.
FROM python:3.9-slim-buster

ENV DEBIAN_FRONTEND=noninteractive

# 2. FIX REPOSITORY ERRORS (The Critical Fix)
# Since Buster is EOL, we must point apt to the archive servers.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list && \
    # Ignore valid-until checks because these archives are old
    apt-get -o Acquire::Check-Valid-Until=false update

# 3. Install Dependencies
RUN apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    openssl \
    nmap \
    curl \
    git \
    nano \
    && rm -rf /var/lib/apt/lists/*

# 4. Create User
RUN useradd --create-home --shell /bin/bash scanner


WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. NUCLEAR OPENSSL OVERRIDE
# We allow everything down to SSLv3 and enable legacy server connect.
RUN echo 'openssl_conf = default_conf' > /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ default_conf ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'ssl_conf = ssl_sect' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ ssl_sect ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'system_default = system_default_sect' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '' >> /etc/ssl/openssl-unsafe.cnf && \
    echo '[ system_default_sect ]' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'MinProtocol = None' >> /etc/ssl/openssl-unsafe.cnf && \
    echo 'CipherString = ALL:@SECLEVEL=0' >> /etc/ssl/openssl-unsafe.cnf

# Force OpenSSL to use our custom unsafe config globally
ENV OPENSSL_CONF=/etc/ssl/openssl-unsafe.cnf

# 7. Copy App and Run
COPY . /app
RUN chown -R scanner:scanner /app

USER scanner
CMD ["python3", "main.py"]