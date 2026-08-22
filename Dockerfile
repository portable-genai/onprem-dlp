# CPU-only, on-prem image. No cloud SDKs, no GPUs, no external calls at runtime.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

# Tesseract enables the image pipeline; drop this line for a text/columns-only image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY requirements-runtime.lock ./
COPY src ./src
COPY config ./config
# Locked, reproducible install: the committed lockfile pins every transitive dep; install
# the package itself with --no-deps so the lock stays authoritative.
RUN pip install --no-cache-dir -r requirements-runtime.lock && pip install --no-cache-dir --no-deps .

# non-root: the gate reads text and samples; it needs no privileges
RUN useradd --create-home dlp
USER dlp

EXPOSE 8484
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/healthz')"

# The REST surface authenticates nobody, so the bind decision does not live in this string:
# onprem_dlp.api.serve resolves it through the fail-closed guard in onprem_dlp/netguard.py and
# binds 127.0.0.1 unless ONPREM_DLP_API_HOST names another host AND
# ONPREM_DLP_ALLOW_UNAUTHENTICATED_EXPOSURE=1 accepts the exposure. The Helm chart sets both,
# because a pod must bind its pod IP for the Service and the kubelet probes to reach it, and
# it compensates with a default-deny NetworkPolicy. The HEALTHCHECK above stays on loopback
# and therefore works in either posture.
CMD ["python", "-m", "onprem_dlp.api.serve"]
