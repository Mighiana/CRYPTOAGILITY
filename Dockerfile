# CryptoAgility Lab image: Python 3.12 + project-local OpenSSL 3.5.9 LTS (checksum-pinned source
# build). The base image's system OpenSSL is not modified or used by the lab.
FROM python:3.12.12-slim-bookworm AS openssl-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential perl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY scripts/setup-openssl.sh scripts/setup-openssl.sh
RUN BUILD_JOBS="$(nproc)" scripts/setup-openssl.sh && rm -rf .tools/cache

FROM python:3.12.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/lab/.tools/openssl/bin:$PATH
RUN groupadd --gid 1000 lab && useradd --uid 1000 --gid lab --create-home lab \
    && mkdir -p /results /pki && chown lab:lab /results /pki
WORKDIR /lab
COPY --from=openssl-build /lab/.tools/openssl /lab/.tools/openssl
COPY pyproject.toml README.md ./
COPY cryptoagility cryptoagility
COPY policies policies
COPY scenario scenario
COPY docker docker
RUN pip install --quiet -e . && cryptoagility --openssl-version
USER lab
ENTRYPOINT ["cryptoagility"]
CMD ["--help"]
