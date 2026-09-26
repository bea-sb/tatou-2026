# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim
# added utf-8 but server still wont start
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
#Added keys copy
COPY keys/server_pub.asc /app/keys/server_pub.asc
COPY keys/server_priv.asc /app/keys/server_priv.asc
COPY keys/clients /app/keys/clients

COPY entrypoint.sh /app/entrypoint.sh
COPY test /app/test
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

