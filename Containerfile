FROM docker.io/library/alpine:3.21
RUN apk add --no-cache strace file binutils bash coreutils yara
WORKDIR /work
COPY analyze.sh /usr/local/bin/analyze.sh
COPY rules/ /opt/yara-rules/
RUN cat /opt/yara-rules/*.yar > /opt/all-rules.yar \
 && yara /opt/all-rules.yar /etc/hostname
RUN chmod +x /usr/local/bin/analyze.sh
ENTRYPOINT ["/usr/local/bin/analyze.sh"]
