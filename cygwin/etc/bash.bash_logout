# To the extent possible under law, the author(s) have dedicated all 
# copyright and related and neighboring rights to this software to the 
# public domain worldwide. This software is distributed without any warranty. 
# You should have received a copy of the CC0 Public Domain Dedication along 
# with this software. 
# If not, see <http://creativecommons.org/publicdomain/zero/1.0/>. 

# base-files version 4.3-3

# /etc/bash.bash_logout: executed by bash(1) when login shell exits.

# The latest version as installed by the Cygwin Setup program can
# always be found at /etc/defaults/etc/bash.bash_logout

# Modifying /etc/bash.bash_logout directly will prevent
# setup from updating it.

# System-wide bashrc file

# when leaving the console clear the screen to increase privacy
if [ "$SHLVL" = 1 ]; then
  [ -x /usr/bin/clear ] && /usr/bin/clear
fi
