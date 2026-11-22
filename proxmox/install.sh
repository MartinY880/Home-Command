#!/usr/bin/env bash
# Home Command for Proxmox VE: creates a small Debian container and installs Home Command in it.
# Run on the Proxmox host as root:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/MartinY880/Home-Command/main/proxmox/install.sh)"
# Run the same line again later to update an existing install.
#
# Optional settings, placed in front of "bash":  HC_CTID=123  HC_HOSTNAME=homecommand  HC_CORES=2  HC_MEMORY=2048
#   HC_DISK=16  HC_STORAGE=local-lvm  HC_BRIDGE=vmbr0  HC_YES=1 (do not ask)  HC_SRC=/path/to/source.tar.gz (offline)
set -euo pipefail
REPO="https://github.com/MartinY880/Home-Command"; TARBALL="${HC_TARBALL:-$REPO/archive/refs/heads/main.tar.gz}"
NAME="${HC_HOSTNAME:-homecommand}"; CORES="${HC_CORES:-2}"; MEM="${HC_MEMORY:-2048}"; DISK="${HC_DISK:-16}"; BRIDGE="${HC_BRIDGE:-vmbr0}"
say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }; die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "Run this as root on the Proxmox host."
command -v pct >/dev/null && command -v pvesm >/dev/null || die "This script must run on a Proxmox VE host (pct not found)."
ask() { [ "${HC_YES:-}" = 1 ] && return 0; [ -t 0 ] || return 0; read -r -p "$1 [Y/n] " a; case "$a" in [nN]*) return 1;; *) return 0;; esac; }

# Is Home Command already installed in a container here? Then update it.
CTID="${HC_CTID:-}"
if [ -z "$CTID" ]; then
  for id in $(pct list 2>/dev/null | awk 'NR>1{print $1}'); do
    if pct config "$id" 2>/dev/null | grep -q "^hostname: $NAME\$"; then CTID="$id"; EXISTING=1; break; fi
  done
elif pct status "$CTID" >/dev/null 2>&1; then EXISTING=1; fi

install_inside() {   # fetch the program into the container and run its installer
  local id="$1"
  if [ -n "${HC_SRC:-}" ]; then pct push "$id" "$HC_SRC" /root/homecommand-src.tar.gz
  else pct exec "$id" -- bash -c "curl -fsSL '$TARBALL' -o /root/homecommand-src.tar.gz" || die "Could not download $TARBALL from inside the container. Check its internet access."; fi
  pct exec "$id" -- bash -c 'set -e; rm -rf /root/homecommand-src; mkdir -p /root/homecommand-src; tar -xzf /root/homecommand-src.tar.gz -C /root/homecommand-src --strip-components=1; rm /root/homecommand-src.tar.gz; cd /root/homecommand-src; LC_ALL=C sh ./install.sh'
}
ct_ip() { pct exec "$1" -- sh -c "hostname -I 2>/dev/null | awk '{print \$1}'"; }

if [ "${EXISTING:-}" = 1 ]; then
  say "Home Command is already in container $CTID. This will update the program; your data and settings are kept."
  ask "Update container $CTID?" || exit 0
  [ "$(pct status "$CTID" | awk '{print $2}')" = running ] || pct start "$CTID"
  install_inside "$CTID"
  say "Updated. Open http://$(ct_ip "$CTID"):3000"
  exit 0
fi

# New install.
CTID="${CTID:-$(pvesh get /cluster/nextid)}"
STORAGE="${HC_STORAGE:-$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')}"
[ -n "$STORAGE" ] || die "No storage that can hold containers was found. Set HC_STORAGE=name."
TSTORE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
[ -n "$TSTORE" ] || die "No storage that can hold container templates was found."
TEMPLATE="$(pveam list "$TSTORE" 2>/dev/null | awk '/debian-13-standard/{print $1}' | sort | tail -1)"
if [ -z "$TEMPLATE" ]; then
  say "Downloading the Debian 13 container template"
  pveam update >/dev/null 2>&1 || true
  T="$(pveam available --section system 2>/dev/null | awk '/debian-13-standard/{print $2}' | sort | tail -1)"
  [ -n "$T" ] || die "Could not find a Debian 13 template to download."
  pveam download "$TSTORE" "$T" >/dev/null || die "Template download failed."
  TEMPLATE="$TSTORE:vztmpl/$T"
fi
say "About to create container $CTID \"$NAME\": $CORES cores, $MEM MB memory, $DISK GB disk on $STORAGE, network $BRIDGE (DHCP)."
ask "Continue?" || exit 0
pct create "$CTID" "$TEMPLATE" --hostname "$NAME" --cores "$CORES" --memory "$MEM" --swap 512 --rootfs "$STORAGE:$DISK" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp,type=veth" --unprivileged 1 --features nesting=1 --onboot 1 --timezone host --ostype debian \
  --description "Home Command portal. $REPO" >/dev/null || die "Could not create the container."
pct start "$CTID"
say "Waiting for the container's network"
for i in $(seq 1 30); do pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null 2>&1' && break; sleep 2; [ "$i" = 30 ] && die "The container has no internet access. Check bridge $BRIDGE and DHCP, then run this again with HC_CTID=$CTID."; done
say "Installing Home Command (a few minutes)"
pct exec "$CTID" -- bash -c 'export DEBIAN_FRONTEND=noninteractive LC_ALL=C; apt-get update -q >/dev/null && apt-get install -y -q curl ca-certificates >/dev/null'
install_inside "$CTID"
IP="$(ct_ip "$CTID")"
say "Done. Home Command is running in container $CTID."
echo
echo "    Open  http://$IP:3000  to choose a password and start the walkthrough."
echo
echo "    Tip: give $IP a fixed address in your gateway so your gateway and log helpers can always find it."
echo "    In UniFi, send the gateway log to $IP port 5514 (the walkthrough explains where)."
