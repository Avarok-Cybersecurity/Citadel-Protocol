FROM alpine
RUN apk add --no-cache iproute2
COPY /docker/network/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
