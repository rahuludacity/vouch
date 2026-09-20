# Vouch runtime image. Stdlib-only except PyYAML (policy files) and the
# Docker SDK (runner needs it to drive the host Docker daemon for real
# sandboxed agent runs; without it the runner only offers the fake backend).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir pyyaml docker
COPY . /app

# Overridden per service in docker-compose.yml.
CMD ["python", "-m", "gatekeeper.proxy"]
