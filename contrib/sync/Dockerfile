FROM alpine

RUN set -x\
    && apk add --no-cache tini openssh-server openssh-client rsync nss_wrapper

COPY entrypoint.sh /

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
