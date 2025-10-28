# Multi-stage Dockerfile:
# The `builder` stage compiles the binary and gathers all dependencies in the `/export/` directory.
FROM debian:13 AS builder
RUN apt-get update && apt-get -y upgrade \
 && apt-get -y install wget curl build-essential gcc make libssl-dev pkg-config git

RUN groupadd -g 1000 ars3nal
RUN useradd -g 1000 -s /bin/sh -d /ars3nal ars3nal

RUN wget -O /usr/local/sbin/gosu https://github.com/tianon/gosu/releases/download/1.19/gosu-amd64 \
 && chmod 0755 /usr/local/sbin/gosu

# Install the latest Rust build environment.
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install the `depres` utility for dependency resolution.
RUN cd /usr/local/src/ \
 && git clone https://github.com/rrauch/depres.git \
 && cd depres \
 && git checkout 717d0098751024c1282d42c2ee6973e6b53002dc \
 && cargo build --release \
 && cp target/release/depres /usr/local/bin/

COPY Cargo.* /usr/local/src/ars3nal/
COPY arfs/ /usr/local/src/ars3nal/arfs/
COPY ario-client/ /usr/local/src/ars3nal/ario-client/
COPY ario-core/ /usr/local/src/ars3nal/ario-core/
COPY ars3nal/ /usr/local/src/ars3nal/ars3nal/
COPY foyer-cache/ /usr/local/src/ars3nal/foyer-cache/

# Build the `ars3nal` binary.
RUN cd /usr/local/src/ars3nal/ars3nal/ \
 && cargo build --release \
 && cp ../target/release/ars3nal /usr/local/bin/

# Add entrypoint-wrapper script to ensure correct permissions in data dir
RUN cat <<'EOF' >/usr/local/bin/ars3nal-entrypoint
#!/usr/bin/env bash
set -euo pipefail

chown -R ars3nal:ars3nal /ars3nal
exec gosu ars3nal:ars3nal /usr/local/bin/ars3nal "$@"
EOF
RUN chmod +x /usr/local/bin/ars3nal-entrypoint

# Use `depres` to identify all required files for the final image.
RUN depres /bin/sh /bin/bash /bin/ls /usr/local/bin/ars3nal \
    /usr/bin/chown \
    /usr/local/sbin/gosu \
    /usr/local/bin/ars3nal-entrypoint \
    /etc/ssl/certs/ \
    /usr/share/ca-certificates/ \
    >> /tmp/export.list

# Copy all required files into the `/export/` directory.
RUN cat /tmp/export.list \
 # remove all duplicates
 && cat /tmp/export.list | sort -o /tmp/export.list -u - \
 && mkdir -p /export/ \
 && rm -rf /export/* \
 # copying all necessary files
 && cat /tmp/export.list | xargs cp -a --parents -t /export/ \
 && mkdir -p /export/tmp && chmod 0777 /export/tmp

RUN mkdir -p /export/etc/ \
 && cat /etc/passwd | grep ars3nal >> /export/etc/passwd \
 && cat /etc/group | grep ars3nal >> /export/etc/group


# The final stage creates a minimal image with all necessary files.
FROM scratch
WORKDIR /

# Copy files from the `builder` stage.
COPY --from=builder /export/ /

VOLUME /ars3nal
EXPOSE 6767
ENV CONFIG="/ars3nal/ars3nal.toml"
ENV DATA="/ars3nal/data/"
ENV METADATA_CACHE="/ars3nal/cache/metadata/"
ENV CHUNK_CACHE="/ars3nal/cache/chunk/"
ENV HOST="0.0.0.0"

ENV HOME="/ars3nal"

ENTRYPOINT ["/usr/local/bin/ars3nal-entrypoint"]
