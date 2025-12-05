# To the extent possible under law, the author(s) have dedicated all 
# copyright and related and neighboring rights to this software to the 
# public domain worldwide. This software is distributed without any warranty. 
# You should have received a copy of the CC0 Public Domain Dedication along 
# with this software. 
# If not, see <http://creativecommons.org/publicdomain/zero/1.0/>. 

# base-files version 4.3-3

# /etc/bash.bashrc: executed by bash(1) for interactive shells.

# The latest version as installed by the Cygwin Setup program can
# always be found at /etc/defaults/etc/bash.bashrc

# Modifying /etc/bash.bashrc directly will prevent
# setup from updating it.

# System-wide bashrc file

# Check that we haven't already been sourced.
[[ -z ${CYG_SYS_BASHRC} ]] && CYG_SYS_BASHRC="1" || return

fix_path()
{
	local IFS=':'
	for p in $PATH; do
		[ "$p" = /usr/local/bin ] && return
	done
	export PATH="/usr/local/bin:/usr/bin:$PATH"
}

fix_path

# If not running interactively, don't do anything
[[ "$-" != *i* ]] && return

# Exclude *dlls from TAB expansion
export EXECIGNORE="*.dll"

# Set a default prompt of: user@host and current_directory
PS1='\[\e]0;\w\a\]\n\[\e[32m\]\u@\h \[\e[33m\]\w\[\e[0m\]\n\$ '

# Uncomment to use the terminal colours set in DIR_COLORS
# eval "$(dircolors -b /etc/DIR_COLORS)"

export LANG=en_US.UTF-8
HISTSIZE=1000
HISTFILESIZE=0
alias ls='ls --color=auto'
alias ll="ls -la"

CYGROOT="$(cygpath -am /)"
BUNDLE_ROOT="$(cygpath -am "$CYGROOT/..")"
alias winws="'$BUNDLE_ROOT/blockcheck/zapret/nfq/winws'"
alias winws2="'$BUNDLE_ROOT/blockcheck/zapret2/nfq2/winws2'"
alias winws2-antidpi="'$BUNDLE_ROOT/blockcheck/zapret2/nfq2/winws2' --lua-init='@$BUNDLE_ROOT/blockcheck/zapret2/lua/zapret-lib.lua' --lua-init='@$BUNDLE_ROOT/blockcheck/zapret2/lua/zapret-antidpi.lua'"
alias mdig="'$BUNDLE_ROOT/blockcheck/zapret/mdig/mdig'"
alias ip2net="'$BUNDLE_ROOT/blockcheck/zapret/ip2net/ip2net'"
alias blockcheck="'$BUNDLE_ROOT/blockcheck/zapret/blockcheck.sh'"
alias blockcheck-kyber="CURL=curl-kyber '$BUNDLE_ROOT/blockcheck/zapret/blockcheck.sh'"
alias blockcheck2="'$BUNDLE_ROOT/blockcheck/zapret2/blockcheck2.sh'"
alias blockcheck2-kyber="CURL=curl-kyber '$BUNDLE_ROOT/blockcheck/zapret2/blockcheck2.sh'"
alias
