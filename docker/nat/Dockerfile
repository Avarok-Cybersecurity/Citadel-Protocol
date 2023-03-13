FROM alpine
RUN apk add --no-cache iptables iproute2
COPY /docker/nat/nat.sh /nat.sh
CMD ["/nat.sh"]