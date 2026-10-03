#!/bin/sh
# A daemon that fails fast with an error on stderr.
echo 'Error: missing required setting p2p_node_addr' >&2
exit 2
