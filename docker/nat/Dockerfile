FROM alpine
RUN apk add --no-cache iptables
COPY /docker/nat/nat.sh /nat.sh
CMD ["/nat.sh"]