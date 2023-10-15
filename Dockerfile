FROM golang:1.21 as builder
ADD . /src
RUN cd /src && CGO_ENABLED=0 go build ./cmd/whawty-auth

FROM scratch
COPY --from=builder /src/whawty-auth /whawty-auth
ENTRYPOINT [ "/whawty-auth" ]
CMD [ "--store", "/config/store.yml", "run", "--web-addr", ":8000" ]
