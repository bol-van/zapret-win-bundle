#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

CURL=curl-kyber exec "$EXEDIR/blog.sh"
