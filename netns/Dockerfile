# Holds the sandbox's network namespace and its firewall. The agent container
# joins this namespace (network_mode: service:netns) WITHOUT CAP_NET_ADMIN.
FROM alpine:3.22
RUN apk add --no-cache iptables ip6tables iproute2
COPY firewall.sh /firewall.sh
ENTRYPOINT ["/bin/sh", "/firewall.sh"]
