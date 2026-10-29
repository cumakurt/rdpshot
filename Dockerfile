# syntax=docker/dockerfile:1

# rdpshot - RDP security-audit platform.
#
# Only scan systems you are authorized to test. Credential checks and
# screenshot capture require an explicit authorization acknowledgement
# (--ack-authorized) and stay disabled by default.
#
# Build targets:
#   slim (default) - distroless static runtime, web UI and scanning only.
#   full           - Alpine runtime with FreeRDP, Xvfb and ImageMagick so the
#                    screenshot capture stage works inside the container.
#
# Build examples:
#   docker build -t rdpshot .
#   docker build --target full -t rdpshot:full .

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM golang:1.27-alpine AS builder

ARG VERSION=dev

WORKDIR /src

# Dependencies first so the module cache layer survives source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/rdpshot ./cmd/rdpshot

# Data directory owned by the runtime user so fresh named volumes inherit the
# ownership and the non-root process can write results.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# ---------------------------------------------------------------------------
# full: Alpine runtime with in-container screenshot capture tooling.
# Build with --target full.
# ---------------------------------------------------------------------------
FROM alpine:3.24 AS full

# freerdp2 ships the "xfreerdp" client the screenshot grabber invokes.
# ImageMagick 7 ships "magick"; the compatibility symlink below provides the
# legacy "import" name the grabber looks for first.
RUN apk add --no-cache bash ca-certificates freerdp2 imagemagick xauth xvfb xvfb-run \
    && if ! command -v xfreerdp >/dev/null 2>&1 && command -v xfreerdp3 >/dev/null 2>&1; then \
         ln -s "$(command -v xfreerdp3)" /usr/bin/xfreerdp; \
       fi \
    && if ! command -v import >/dev/null 2>&1 && command -v magick >/dev/null 2>&1; then \
         ln -s "$(command -v magick)" /usr/bin/import; \
       fi

RUN adduser -D -H -u 65532 rdpshot && mkdir -p /data && chown 65532:65532 /data

COPY --from=builder /out/rdpshot /usr/bin/rdpshot
COPY --from=builder /src/wordlists /usr/share/rdpshot/wordlists

# The built-in wordlist defaults are relative paths; point them at the copies
# shipped in the image so credential audits work without extra flags. Both
# values are file paths, not credentials (the Dockerfile linter flags the
# *_PASSWORD_WORDLIST name as a possible secret).
ENV RDSHOT_USER_WORDLIST=/usr/share/rdpshot/wordlists/default_users.txt \
    RDSHOT_PASSWORD_WORDLIST=/usr/share/rdpshot/wordlists/default_passwords.txt

WORKDIR /data

EXPOSE 8722
VOLUME ["/data"]

USER rdpshot

ENTRYPOINT ["/usr/bin/rdpshot"]
CMD ["serve", "--addr", "0.0.0.0:8722", "--db", "/data/rdpshot.db", "--outputs", "/data"]

# ---------------------------------------------------------------------------
# slim (default, final stage): distroless static runtime without capture
# tooling. Screenshot requests inside this image report the missing tooling
# and are skipped; use --target full for in-container captures.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS slim

COPY --from=builder /out/rdpshot /usr/bin/rdpshot
COPY --from=builder /src/wordlists /usr/share/rdpshot/wordlists
COPY --from=builder --chown=65532:65532 /out/data /data

# The built-in wordlist defaults are relative paths; point them at the copies
# shipped in the image so credential audits work without extra flags.
ENV RDSHOT_USER_WORDLIST=/usr/share/rdpshot/wordlists/default_users.txt \
    RDSHOT_PASSWORD_WORDLIST=/usr/share/rdpshot/wordlists/default_passwords.txt

WORKDIR /data

EXPOSE 8722
VOLUME ["/data"]

USER nonroot:nonroot

ENTRYPOINT ["/usr/bin/rdpshot"]
CMD ["serve", "--addr", "0.0.0.0:8722", "--db", "/data/rdpshot.db", "--outputs", "/data"]