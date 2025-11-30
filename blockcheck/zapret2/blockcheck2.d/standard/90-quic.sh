pktws_check_http3()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_QUIC" = 1 ] && { echo "SKIPPED"; return; }

	local repeats fake pos
	local PAYLOAD="--payload quic_initial"

	if [ -n "$FAKE_QUIC" ]; then
		fake=fake_quic
	else
		fake=fake_default_quic
	fi

	for repeats in 1 2 5 10 20; do
		pktws_curl_test_update $1 $2 ${FAKE_QUIC:+--blob=$fake:@"$FAKE_QUIC" }$PAYLOAD --lua-desync=fake:blob=$fake:repeats=$repeats && [ "$SCANLEVEL" != force ] && break
	done

	for pos in 8 16 32 64; do
		pktws_curl_test_update $1 $2 $PAYLOAD --lua-desync=send:ipfrag:ipfrag_pos_udp=$pos --lua-desync=drop && [ "$SCANLEVEL" != force ] && break
	done

	for pos in 8 16 32 64; do
		pktws_curl_test_update $1 $2 ${FAKE_QUIC:+--blob=$fake:@"$FAKE_QUIC" }$PAYLOAD --lua-desync=fake:blob=$fake:repeats=$FAKE_REPEATS --lua-desync=send:ipfrag:ipfrag_pos_udp=$pos --lua-desync=drop && [ "$SCANLEVEL" != force ] && break
	done
}
