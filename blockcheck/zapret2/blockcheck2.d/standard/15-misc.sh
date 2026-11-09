. "$TESTDIR/def.inc"

pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	local PAYLOAD="--payload=http_req" repeats ok

	[ "$NOTEST_MISC_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	for repeats in 1 20 100 260; do
		# send starting bytes of original payload
		pktws_curl_test_update "$1" "$2" $PAYLOAD --lua-desync=tcpseg:pos=0,method+2:ip_id=rnd:repeats=$repeats && ok=1
		pktws_curl_test_update "$1" "$2" $PAYLOAD --lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=$repeats && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" != force ] && break
	done
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	local PAYLOAD="--payload=tls_client_hello" repeats ok

	[ "$NOTEST_MISC_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	for repeats in 1 20 100 260; do
		# send starting bytes of original payload
		pktws_curl_test_update "$1" "$2" $PAYLOAD --lua-desync=tcpseg:pos=0,1:ip_id=rnd:repeats=$repeats && ok=1
		pktws_curl_test_update "$1" "$2" $PAYLOAD --lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=$repeats && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" != force ] && break
	done
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls12 "$1" "$2"
}
