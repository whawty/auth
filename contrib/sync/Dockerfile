FROM golang:1.21 as builder
ARG GOKR_RSYNC_VERSION=0.1.0
RUN CGO_ENABLED=0 go install github.com/gokrazy/rsync/cmd/gokr-rsync@v${GOKR_RSYNC_VERSION} github.com/gokrazy/rsync/cmd/gokr-rsyncd@v${GOKR_RSYNC_VERSION}

FROM scratch
COPY --from=builder /go/bin/ /
