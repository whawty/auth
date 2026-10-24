# The binary is cross-compiled on the platform of the build host, which is much
# faster than compiling it in an emulated container of the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
ARG TARGETOS TARGETARCH TARGETVARIANT
# the version printed by --version, the release build passes the one of the release tag
ARG VERSION
ADD . /src
RUN cd /src && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} go build -ldflags "${VERSION:+-X main.version=$VERSION}" ./cmd/whawty-auth

FROM scratch
COPY --from=builder /src/whawty-auth /whawty-auth
ENTRYPOINT [ "/whawty-auth" ]
CMD [ "--store", "/config/store.yml", "run", "--listener", "/config/listener.yml" ]
