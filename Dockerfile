# Plate — single binary, two commands (spec Q4). This image is used for both
# `plate serve` (API) and, later, `plate work` (worker); Phase 1 ships only the
# read-path API. Multi-stage so the runtime image carries just the static binary.
FROM golang:1.27-alpine AS build
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO off → a static binary that runs on a scratch/alpine base unchanged.
RUN CGO_ENABLED=0 go build -o /out/plate ./cmd/plate

FROM alpine:3.20
# ca-certificates for outbound TLS (R2, etc). ffmpeg is NOT installed here — the
# read-path API does not transcode; the worker image (Phase 2) adds it.
RUN apk add --no-cache ca-certificates
COPY --from=build /out/plate /usr/local/bin/plate
EXPOSE 8080
# Default to the API. `docker run … plate work` selects the worker command.
ENTRYPOINT ["plate"]
CMD ["serve"]
