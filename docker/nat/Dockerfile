FROM alpine
ARG NAT_TYPE
RUN export NAT_TYPE=$NAT_TYPE

RUN apk add --no-cache iproute2 iptables
COPY ./docker/nat/set_nat.sh /set_nat.sh
ENTRYPOINT ["/set_nat.sh"]