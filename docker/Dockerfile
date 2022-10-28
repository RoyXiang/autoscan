FROM golang:1.17 AS builder

ARG \
    COMMIT \
    TIMESTAMP \
    VERSION

ENV CGO_ENABLED=0

WORKDIR /go/src/github.com/cloudbox/autoscan/

COPY . .

RUN go build -v -trimpath \
        -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.GitCommit=${COMMIT}' -X 'main.Timestamp=${TIMESTAMP}'" \
        -o /go/bin/autoscan \
        ./cmd/autoscan

FROM gcr.io/distroless/base-debian11:nonroot

COPY --from=builder --chown=nonroot /go/bin/autoscan /usr/local/bin/

USER nonroot

EXPOSE 3030

ENTRYPOINT ["/usr/local/bin/autoscan"]
