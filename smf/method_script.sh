#!/bin/bash
#
# SMF start method for the thundermuffin membership service.
#
# The service holds multicast group memberships open on behalf of a zone that
# has no listening application of its own. For each configured group it spawns
# a "joiner": a `thundermuffin server` process whose only purpose is to keep
# the kernel's IGMP/MLD membership for that group established on the pinned
# interface. The illumos IP stack accepts (and answers ICMP echo for) only
# locally joined groups, so the joiners supply the membership state the
# zone's stack needs to accept group traffic. Forwarding to the port is
# programmed separately by the control plane.
#
# This must run inside the zone: IGMP/MLD membership is per-netstack state,
# and a zone with an exclusive IP stack cannot receive it from outside. The
# sled-agent, as a global-zone process, can only join groups in the GZ
# netstack. The joiners stand in for the guest workload that performs the
# in-guest join on actual instances.
#
# The script blocks on the joiners to keep the start method's process
# contract populated. If any joiner dies the whole instance restarts and
# every membership is re-established.

set -o errexit
set -o pipefail
set -o nounset

export RUST_LOG=info

BIN=/opt/oxide/thundermuffin/bin/thundermuffin
if [[ ! -x "$BIN" ]]; then
    echo "thundermuffin binary not found at $BIN" >&2
    exit 1
fi

port=$(svcprop -c -p config/port "${SMF_FMRI}")

# IPv4 address bound to the interface the joins should be pinned to (the
# probe's overlay port). For multicast this becomes IP_MULTICAST_IF and, for
# SSM, pins the source-specific membership to that interface.
#
# Note: this may be unset.
iface=$(svcprop -c -p config/multicast_iface "${SMF_FMRI}" 2>/dev/null || true)
if [[ "$iface" == '""' ]]; then
    iface=""
fi

# Multi-valued list of multicast groups to join and hold open. The illumos IP
# stack only accepts (and only answers ICMP echo for) a group the interface
# has locally joined, so a probe with no listening application needs this
# long-lived membership to respond to reachability probes. Forwarding to the
# port is programmed statically by the control plane, as this is solely the
# host-local membership gate.
groups=$(svcprop -c -p config/multicast_group "${SMF_FMRI}" 2>/dev/null || true)
if [[ "$groups" == '""' ]]; then
    groups=""
fi

# Interface index (ifindex) the IPv6 joins should be pinned to. IPv6 has no
# address-based IP_MULTICAST_IF equivalent, so the binary takes a numeric
# `--scope` instead (IPV6_MULTICAST_IF, and the SSM join interface). A value
# of 0 means kernel-selected and is the binary's default, so it is elided.
ipv6_scope=$(svcprop -c -p config/ipv6_scope "${SMF_FMRI}" 2>/dev/null || echo 0)

iface_args=()
if [[ -n "$iface" ]]; then
    iface_args=(--multicast-iface "$iface")
fi
if [[ "$ipv6_scope" != 0 ]]; then
    iface_args+=(--scope "$ipv6_scope")
fi

if [[ -z "$groups" ]]; then
    # No groups configured. Stay online but idle so the service does not
    # flap. The sled-agent rewrites config and restarts the service when
    # membership changes.
    echo "no multicast groups configured; idling" >&2
    exec sleep infinity
fi

# Spawn one joiner per group.
pids=()
for entry in $groups; do
    # svcprop -c quotes each astring value, so strip the surrounding quotes.
    entry=${entry#\"}
    entry=${entry%\"}
    [[ -z "$entry" ]] && continue
    # sled-agent encodes a source-specific (SSM) membership as
    # `group@src1,src2` and an any-source (ASM) membership as a bare `group`.
    # The `@` separator is not a shell metacharacter, so svcprop emits it
    # verbatim.
    #
    # We split off the optional source list and pass one `--multicast-source`
    # per source so an SSM group gets the INCLUDE-mode (S, G) join it requires.
    group=${entry%%@*}
    src_args=()
    if [[ "$entry" == *"@"* ]]; then
        sources=${entry#*@}
        IFS=',' read -ra src_list <<< "$sources"
        for src in "${src_list[@]}"; do
            [[ -z "$src" ]] && continue
            src_args+=(--multicast-source "$src")
        done
    fi
    "$BIN" --transport udp --port "$port" "${iface_args[@]}" \
        server "$group" "${src_args[@]}" &
    pids+=("$!")
done

# If every entry stripped to an empty string (e.g., a multi-valued property
# holding only empty values), no joiners would be started. We remain idle
# instead of calling `wait -n` with no pids, which returns 127 and would
# restart-loop the service.
if ((${#pids[@]} == 0)); then
    echo "no non-empty multicast groups configured; idling" >&2
    exec sleep infinity
fi

# Block on the joiners to keep the start method's process contract (created
# by ctrun in the manifest) populated. If any joiner exits, this script exits
# too. ctrun's noorphan option then kills the surviving joiners, the contract
# empties, and svc.startd restarts the instance, re-establishing every
# membership.
#
# The explicit exit covers the clean-exit path. On a nonzero status, errexit
# already terminates the script at the wait itself. Either way, the script
# exits with the first-reaped joiner's status, which only surfaces in the
# service log. The restart is driven by the emptied contract (startd/duration),
# not by the status.
wait -n "${pids[@]}"
exit $?
