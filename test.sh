#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025, Matthieu Baerts.

export NS=tcp
export HOSTS=(cli cpe int net srv)

netns()
{
	local suffix
	local nss=()
	for suffix in "${HOSTS[@]}"; do
		nss+=("${NS}_${suffix}")
	done
	echo "${nss[@]}"
}

cleanup()
{
	local suffix
	for suffix in "${HOSTS[@]}"; do
		local ns="${NS}_${suffix}"
		echo "== ${suffix} =="
		ip netns exec "${ns}" nstat
		ip netns pids "${ns}" | xargs -r kill
		ip netns del "${ns}" >/dev/null 2>&1
	done
}

trap cleanup EXIT

server()
{
	ip netns exec "${NS}_srv" iperf3 -s -D
	sleep .1 # making sure the daemon is launched
}

tc_client()
{
	local ns="${NS}_cpe" iface="int"

	# ip netns will umount everything on exit
	ip netns exec "${ns}" sh -c "mount -t debugfs none /sys/kernel/debug && cat /sys/kernel/debug/tracing/trace_pipe" &

	tc -n "${ns}" qdisc add dev "${iface}" clsact
	tc -n "${ns}" filter add dev "${iface}" egress  bpf da obj tcp_in_udp_tc.o sec tc_egress
	tc -n "${ns}" filter add dev "${iface}" ingress bpf da obj tcp_in_udp_tc.o sec tc_ingress

	tc -n "${ns}" filter show dev "${iface}" egress
	tc -n "${ns}" filter show dev "${iface}" ingress
}

tc_server()
{
	local ns="${NS}_net" iface="int"

	# ip netns will umount everything on exit
	ip netns exec "${ns}" sh -c "mount -t debugfs none /sys/kernel/debug && cat /sys/kernel/debug/tracing/trace_pipe" &

	tc -n "${ns}" qdisc add dev "${iface}" clsact
	tc -n "${ns}" filter add dev "${iface}" egress  bpf da obj tcp_in_udp_tc.o sec tc_egress
	tc -n "${ns}" filter add dev "${iface}" ingress bpf da obj tcp_in_udp_tc.o sec tc_ingress

	tc -n "${ns}" filter show dev "${iface}" egress
	tc -n "${ns}" filter show dev "${iface}" ingress
}

capture()
{
	ip netns exec "${NS}_cli" tcpdump -i cpe -s 100 -w cli_cpe.pcap tcp or udp &
	ip netns exec "${NS}_int" tcpdump -i cpe -s 100 -w int_cpe.pcap tcp or udp &
	ip netns exec "${NS}_int" tcpdump -i net -s 100 -w int_net.pcap tcp or udp &
	ip netns exec "${NS}_srv" tcpdump -i net -s 100 -w srv_net.pcap tcp or udp &
}

setup()
{
	local suffix
	for suffix in "${HOSTS[@]}"; do
		local ns="${NS}_${suffix}"
		ip netns add "${ns}"
		ip -n "${ns}" link set lo up
	done

	#        .0.2  .0.1   .1.2  .1.1   .3.2  .3.1   .2.1  .2.2
	#     cli -------- cpe -------- int -------- net -------- srv

	ip link add "cli" netns "${NS}_cpe" type veth peer name "cpe" netns "${NS}_cli"
	ip link add "cpe" netns "${NS}_int" type veth peer name "int" netns "${NS}_cpe"
	ip link add "int" netns "${NS}_net" type veth peer name "net" netns "${NS}_int"
	ip link add "net" netns "${NS}_srv" type veth peer name "srv" netns "${NS}_net"

	ip -n "${NS}_cli" link set "cpe" up
	ip -n "${NS}_cli" addr add dev "cpe" 10.0.0.2/24
	ip -n "${NS}_cli" route add default via 10.0.0.1 dev "cpe"

	ip -n "${NS}_cpe" link set "cli" up
	ip -n "${NS}_cpe" addr add dev "cli" 10.0.0.1/24
	ip -n "${NS}_cpe" link set "int" up
	ip -n "${NS}_cpe" addr add dev "int" 10.0.1.2/24
	ip -n "${NS}_cpe" route add default via 10.0.1.1 dev "int"

	ip -n "${NS}_int" link set "cpe" up
	ip -n "${NS}_int" addr add dev "cpe" 10.0.1.1/24
	tc -n "${NS}_int" qdisc add dev "cpe" root netem rate 10mbit delay 5ms
	ip -n "${NS}_int" link set "net" up
	ip -n "${NS}_int" addr add dev "net" 10.0.3.2/24
	tc -n "${NS}_int" qdisc add dev "net" root netem rate 10mbit delay 5ms
	ip -n "${NS}_int" route add 10.0.0.0/24 via 10.0.1.2 dev "cpe"
	ip -n "${NS}_int" route add 10.0.2.0/24 via 10.0.3.1 dev "net"

	ip -n "${NS}_net" link set "int" up
	ip -n "${NS}_net" addr add dev "int" 10.0.3.1/24
	ip -n "${NS}_net" link set "srv" up
	ip -n "${NS}_net" addr add dev "srv" 10.0.2.1/24
	ip -n "${NS}_net" route add default via 10.0.3.2 dev "int"

	ip -n "${NS}_srv" link set "net" up
	ip -n "${NS}_srv" addr add dev "net" 10.0.2.2/24
	ip -n "${NS}_srv" route add default via 10.0.2.1 dev "net"
}

setup
server
capture

tc_client
tc_server

case "${1}" in
	*)
		export -f tc_client tc_server
		echo -e "\n\tNetns: $(netns)\n\tUse 'ip netns exec <NETNS> <CMD>' to execute a command in the netns.\n\tServer: iperf3 -c 10.0.2.2 -R\n"
		PS1="client# " ip netns exec ${NS}_cli sh -c "mount -t debugfs none /sys/kernel/debug && bash"
		;;
esac
