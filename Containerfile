FROM docker.io/library/alpine:3.21
RUN apk add --no-cache strace file binutils bash coreutils
WORKDIR /work
COPY analyze.sh /usr/local/bin/analyze.sh
RUN chmod +x /usr/local/bin/analyze.sh
ENTRYPOINT ["/usr/local/bin/analyze.sh"]
