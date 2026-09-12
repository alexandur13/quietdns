FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
COPY web ./web
ARG VERSION=0.2.0-dev
RUN go mod tidy && go test -v ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /quietdns .

FROM alpine:3.24 AS files
RUN apk add --no-cache ca-certificates && mkdir /data && chown 65532:65532 /data

FROM scratch
COPY --from=files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=files --chown=65532:65532 /data /data
COPY --from=build /quietdns /quietdns
USER 65532:65532
ENV DATA_DIR=/data DNS_ADDR=:1053 HTTP_ADDR=:8080
EXPOSE 1053/udp 1053/tcp 8080/tcp
ENTRYPOINT ["/quietdns"]
