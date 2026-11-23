#!/bin/sh
# Default deny. The sandbox may only reach:
#   gateway:8080   LLM credential gateway
#   relay:*        fixed TCP forwards + allow-listed HTTP egress proxy
#   RE_ALLOW       extra destinations (only when the egress network is attached)
# The Docker/OrbStack host, link-local/metadata and RE_DENY are rejected even if
# RE_ALLOW covers them.
set -eu
log() { echo "[netns] $*"; }
die() { log "FATAL: $*"; exit 1; }
words() { printf '%s' "${1:-}" | tr ',;\n' '   '; }
v4all() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; }
is_v4() { printf '%s' "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$'; }

wait_v4() {
  i=0
  while [ $i -lt 120 ]; do
    ip=$(v4all "$1" | head -n1)
    [ -n "$ip" ] && { echo "$ip"; return 0; }
    i=$((i + 1)); sleep 0.5
  done
  return 1
}

rm -f /run/ready
GW=$(wait_v4 gateway) || die "cannot resolve gateway"
RELAY=$(wait_v4 relay) || die "cannot resolve relay"

# filter table only: Docker's embedded DNS (127.0.0.11) DNAT lives in nat.
for c in INPUT OUTPUT FORWARD; do iptables -F "$c"; done
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$GW" -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -d "$RELAY" -p tcp -j ACCEPT

# Never reachable: Docker/OrbStack host aliases, every attached subnet (bridge
# gateways, other containers), the default gateway, link-local/metadata,
# multicast, 0/8 (OrbStack host services live in 0.250.250.0/24), RE_DENY.
DENY="0.0.0.0/8 169.254.0.0/16 224.0.0.0/3"
for h in host.docker.internal host.orb.internal gateway.docker.internal; do
  DENY="$DENY $(v4all "$h" | tr '\n' ' ')"
done
DENY="$DENY $(ip -4 route show default | awk '{print $3}' | tr '\n' ' ')"
DENY="$DENY $(ip -4 route show proto kernel scope link | awk '{print $1}' | tr '\n' ' ')"
DENY="$DENY $(words "${RE_DENY_CIDRS:-}")"
for d in $DENY; do
  is_v4 "$d" || die "bad deny entry: $d"
  iptables -A OUTPUT -d "$d" -j REJECT --reject-with icmp-admin-prohibited
done

ALLOWED=""
if ip -4 route show default | grep -q .; then
  for spec in $(words "${RE_ALLOW_CIDRS:-}"); do
    port=""
    case "$spec" in
      *:*) port="${spec##*:}"; spec="${spec%:*}" ;;
    esac
    if is_v4 "$spec"; then dsts="$spec"; else dsts=$(v4all "$spec" | tr '\n' ' '); fi
    [ -n "$dsts" ] || die "cannot resolve allow entry: $spec"
    for d in $dsts; do
      if [ -n "$port" ]; then
        printf '%s' "$port" | grep -Eq '^[0-9]{1,5}$' || die "bad port in allow entry: $spec:$port"
        iptables -A OUTPUT -d "$d" -p tcp --dport "$port" -j ACCEPT
        iptables -A OUTPUT -d "$d" -p udp --dport "$port" -j ACCEPT
      else
        iptables -A OUTPUT -d "$d" -j ACCEPT
      fi
      ALLOWED="$ALLOWED $d${port:+:$port}"
    done
  done
elif [ -n "${RE_ALLOW_CIDRS:-}" ]; then
  log "RE_ALLOW_CIDRS set but no egress network attached; ignoring"
fi
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

# IPv6: disabled by sysctl; also drop everything in case it comes back.
if ip6tables -P INPUT DROP 2>/dev/null; then
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
  ip6tables -F INPUT; ip6tables -F OUTPUT; ip6tables -F FORWARD
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
else
  [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = 1 ] || die "ip6tables unavailable and IPv6 enabled"
fi

iptables -S OUTPUT | grep -qx -- '-P OUTPUT DROP' || die "policy not applied"
log "gateway=$GW relay=$RELAY"
log "allowed:${ALLOWED:- (none: isolated mode)}"
log "denied: $DENY"
touch /run/ready
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
