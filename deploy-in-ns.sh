#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025, Matthieu Baerts.

export NS=tcp

cleanup()
{
	return

	local suffix
	ip netns pids "${NS}" | xargs -r kill
	ip netns del "${NS}" >/dev/null 2>&1
}

trap cleanup EXIT

server()
{
	ip netns exec "${NS}" iperf3 -s -D
	sleep 1 # making sure the daemon is launched
}

tc_setup()
{
	local ns="${NS}" iface="nshost"

	# ip netns will umount everything on exit
	ip netns exec "${ns}" sh -c "mount -t debugfs none /sys/kernel/debug && cat /sys/kernel/debug/tracing/trace_pipe" &

	tc -n "${ns}" qdisc add dev "${iface}" clsact
	tc -n "${ns}" filter add dev "${iface}" egress  bpf da obj tcp_in_udp_tc.o sec tc_egress
	tc -n "${ns}" filter add dev "${iface}" ingress bpf da obj tcp_in_udp_tc.o sec tc_ingress

	tc -n "${ns}" filter show dev "${iface}" egress
	tc -n "${ns}" filter show dev "${iface}" ingress

	ip netns exec "${ns}" ethtool -K "${iface}" gro off gso off tso off lro off ufo off sg off
	ethtool -K "eth0" gro off gso off tso off lro off ufo off sg off
}

capture()
{
	ip netns exec "${NS}" tcpdump -i nshost -s 100 -w ns.pcap tcp or udp
}

setup()
{
	ip netns add "${NS}"
	ip -n "${NS}" link set lo up

	ip link add hostns type veth peer name nshost
	ip link set nshost netns "${NS}"

	ip link set hostns up
	ip -n "${NS}" link set nshost up

	ip addr add 10.0.42.1/24 dev hostns
	ip -n "${NS}" addr add 10.0.42.2/24 dev nshost

	ip -n "${NS}" route add default via 10.0.42.1 dev nshost

	# TODO: forward port 5201 + masquerade
}

setup
server
# capture

tc_setup

case "${1}" in
	*)
		export -f capture
		ip netns exec ${NS}_cli sh -c "mount -t debugfs none /sys/kernel/debug && bash"
		;;
esac
