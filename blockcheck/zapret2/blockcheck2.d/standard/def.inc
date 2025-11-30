FOOLINGS46_TCP=${FOOLINGS46_TCP:-"tcp_md5 badsum tcp_seq=-3000 tcp_seq=1000000 tcp_ack=-66000:tcp_ts_up tcp_ts=-1000 tcp_flags_unset=ACK tcp_flags_set=SYN"}
FOOLINGS6_TCP=${FOOLINGS6_TCP:-"ip6_hopbyhop ip6_hopbyhop:ip6_hopbyhop2 ip6_destopt ip6_routing ip6_ah"}
FOOLINGS_TCP="$FOOLINGS46_TCP"
[ "$IPV" = 6 ] && FOOLINGS_TCP="$FOOLINGS_TCP $FOOLINGS6_TCP"
FOOLINGS_UDP="badsum"

FAKE_REPEATS=${FAKE_REPEATS:-1}
