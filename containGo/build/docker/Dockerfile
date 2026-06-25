FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN set -eux; \
    for app in api-gateway control-plane dashboard order-client protected-api report-client; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o "/out/${app}" "./cmd/${app}"; \
    done

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/ /app/
USER 10001:10001
ENTRYPOINT ["/app/dashboard"]
