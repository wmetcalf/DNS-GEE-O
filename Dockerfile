FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /app/bin/dnsgeeo ./cmd/dnsgeeo

FROM python:3.12-slim
WORKDIR /app
ENV DNSGEEO_BIN=/app/bin/dnsgeeo
ENV DNSGEEO_CITY_DB=/app/data/GeoLite2-City.mmdb
ENV DNSGEEO_ASN_DB=/app/data/GeoLite2-ASN.mmdb
COPY --from=builder /app/bin/dnsgeeo /app/bin/dnsgeeo
COPY data ./data
COPY tools ./tools
RUN apt-get update \
  && apt-get install -y --no-install-recommends whois \
  && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r /app/tools/requirements.txt
EXPOSE 8080 9090
CMD ["sh", "/app/tools/serve_all.sh"]
