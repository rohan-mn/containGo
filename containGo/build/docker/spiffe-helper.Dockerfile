FROM golang:1.25-alpine AS builder
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install github.com/spiffe/spiffe-helper/cmd/spiffe-helper@v0.11.0

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/spiffe-helper /usr/local/bin/spiffe-helper
ENTRYPOINT ["/usr/local/bin/spiffe-helper"]
