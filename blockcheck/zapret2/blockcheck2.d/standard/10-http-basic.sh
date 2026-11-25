pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	local s

	[ "$NOTEST_BASIC_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	for s in 'http_hostcase' 'http_hostcase:spell=hoSt' 'http_domcase' 'http_methodeol' 'http_unixeol'; do
		pktws_curl_test_update $1 $2 --payload=http_req --lua-desync=$s
	done
}
