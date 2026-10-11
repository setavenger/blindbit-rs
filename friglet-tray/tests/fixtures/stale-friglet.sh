#!/bin/sh
# A stale daemon build that rejects the zero-argument spawn with a clap
# usage dump.
printf 'A CLI tool\n\nUsage: friglet <COMMAND>\n' >&2
exit 2
