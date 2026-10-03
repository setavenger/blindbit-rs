#!/bin/sh
# Stands in for a daemon that keeps running. exec: killing the child must
# not leave a stray sleep behind.
exec sleep 30
