# Vouch Phase 1 runtime image. Stdlib-only except PyYAML (policy files).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir pyyaml
COPY . /app

# Overridden per service in docker-compose.yml.
CMD ["python", "-m", "gatekeeper.proxy"]
