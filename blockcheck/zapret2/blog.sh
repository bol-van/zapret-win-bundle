#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

"$EXEDIR/blockcheck2.sh" 2>&1 | tee "$EXEDIR/../blockcheck2.log"
# windows 7 notepad does not view unix EOL correctly
unix2dos "$EXEDIR/../blockcheck2.log"
