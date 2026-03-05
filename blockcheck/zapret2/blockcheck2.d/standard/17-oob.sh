. "$TESTDIR/def.inc"

pktws_oob()
{
	# $1 - test function
	# $2 - domain

	local urp
	for urp in b 0 2 midsld; do
		pktws_curl_test_update "$1" "$2" --in-range=-s1 --lua-desync=oob:urp=$urp
	done
}

pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_OOB_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	pktws_oob "$@"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_OOB_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_oob "$@"
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls12 "$1" "$2"
}
