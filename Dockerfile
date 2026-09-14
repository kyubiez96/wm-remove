# wm-remove HF Space image: build context = repository root.
# Adapted from service/Dockerfile (COPY paths adjusted for the root context),
# keeping the same hardening: pinned base by digest, pinned c2patool + sha256,
# pinned pip, unprivileged runtime user.
#
#   docker build -t wm-remove .
#   docker run --rm -p 8765:8765 -e WATERMARKS_SERVER_API_KEY=$KEY wm-remove

ARG C2PATOOL_VERSION=c2patool-v0.27.15
ARG C2PATOOL_SHA256=7a035b727a6cdda8ad08d98fe94b3c20febee4aea4e7c1de02571b295730faf0
ARG VERSION=dev

# python:3.14-slim linux/amd64 digest.
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

ARG C2PATOOL_VERSION
ARG C2PATOOL_SHA256
ARG VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        ffmpeg \
        ghostscript \
        libarchive-zip-perl \
        libimage-exiftool-perl \
        passwd \
        qpdf \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/c2patool.tar.gz \
        "https://github.com/contentauth/c2pa-rs/releases/download/${C2PATOOL_VERSION}/${C2PATOOL_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    && echo "${C2PATOOL_SHA256}  /tmp/c2patool.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/c2patool.tar.gz -C /tmp \
    && install -m 0755 /tmp/c2patool/c2patool /usr/local/bin/c2patool \
    && rm -rf /tmp/c2patool /tmp/c2patool.tar.gz

COPY service/scripts /app/scripts
COPY config /app/config

# COPY preserves the source modes, so a build host with a restrictive umask
# (e.g. 027) lands these as 0640/0750 root:root -- unreadable and untraversable
# for the unprivileged runtime user below. Normalize instead of inheriting it.
RUN chmod -R a+rX /app/scripts /app/config

RUN python3 -m pip install --no-cache-dir "pip==26.2.1"

# Unprivileged runtime user.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin remover
USER remover

ENV WATERMARKS_SERVER_VERSION=${VERSION} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
EXPOSE 8765
# ${PORT}-aware: HF Spaces leave PORT unset (→8765), Render injects PORT.
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec python3 /app/scripts/server.py --host 0.0.0.0 --port ${PORT:-8765}"]