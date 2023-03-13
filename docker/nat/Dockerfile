FROM alpine
RUN apk add --no-cache iptables
COPY nat.sh /nat.sh
CMD ["/nat.sh"]