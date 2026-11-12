#!/bin/sh
# Entry point of the Docker image: the first argument chooses the process.
#
#   mcp [ARGS]          MCP server (default): `security-review-mcp serve` without ARGS, whose
#                       transport follows SECREVIEW_TRANSPORT (http or stdio)
#   controller [ARGS]   Controller server: `security-review-controller serve` without ARGS, or
#                       one of its commands (db, token, user, rules...)
#   scan-engine [ARGS]  scan engine of the Controller server: `security-review-scan-engine`
#   anything else       arguments of security-review-mcp (serve, enroll...), as before
#
# exec replaces this shell: the server is process 1 (signals, health check) and nothing is
# written on stdout, which stdio reserves to the MCP protocol.
set -eu

command="${1:-mcp}"
[ "$#" -gt 0 ] && shift
case "$command" in
    mcp)
        [ "$#" -eq 0 ] && set -- serve
        exec security-review-mcp "$@"
        ;;
    controller)
        [ "$#" -eq 0 ] && set -- serve
        exec security-review-controller "$@"
        ;;
    scan-engine)
        exec security-review-scan-engine "$@"
        ;;
    *)
        exec security-review-mcp "$command" "$@"
        ;;
esac
