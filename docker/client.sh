#!/bin/sh
# Strict clients against the compose servers over a real container network. Each client offers
# exactly one group; a mismatch must fail (no silent downgrade). Exit 1 if any expectation fails.
set -u
export OPENSSL_CONF=/dev/null
failures=0

handshake() { # server group -> sets out, rc
    out="$(openssl s_client -connect "$1:4433" -servername "$1" -tls1_3 -groups "$2" \
        -CAfile "/pki/${1%-server}/ca.pem" -verify_return_error -verify_hostname "$1" \
        </dev/null 2>&1)"
    rc=$?
}

wait_ready() { # server own-group
    i=0
    while :; do
        if [ -f "/pki/${1%-server}/ca.pem" ]; then
            handshake "$1" "$2"
            [ "$rc" -eq 0 ] && return 0
        fi
        i=$((i + 1))
        [ "$i" -ge 90 ] && { echo "$1 not ready" >&2; return 1; }
        sleep 1
    done
}

probe() { # server group expectation
    server="$1"; group="$2"; expect="$3"
    handshake "$server" "$group"
    negotiated="$(printf '%s\n' "$out" | sed -n -e 's/^Negotiated TLS1.3 group: //p' \
        -e 's/^Peer Temp Key: \([^,]*\).*/\1/p' | head -n1)"
    [ "$negotiated" = "<NULL>" ] && negotiated=""
    if [ "$rc" -ne 0 ]; then negotiated=""; fi
    if [ "$expect" = success ] && [ "$rc" -eq 0 ] && [ "$negotiated" = "$group" ]; then
        result=PASS
    elif [ "$expect" = fail ] && [ "$rc" -ne 0 ]; then
        result=PASS
    else
        result=FAIL; failures=$((failures + 1))
    fi
    reason="$(printf '%s\n' "$out" | grep -o 'alert [a-z ]*\|verify error:[^)]*' | head -n1)"
    printf '%-4s %-17s client offers %-15s expected %-7s -> %s\n' "$result" "$server" "$group" \
        "$expect" "${negotiated:-no handshake (${reason:-rc=$rc})}"
}

openssl version
wait_ready classical-server X25519 && wait_ready hybrid-server X25519MLKEM768 \
    && wait_ready pqc-server MLKEM768 || exit 1
probe classical-server X25519 success
probe hybrid-server X25519MLKEM768 success
probe pqc-server MLKEM768 success
probe hybrid-server X25519 fail
probe pqc-server X25519 fail
probe pqc-server X25519MLKEM768 fail
probe classical-server MLKEM768 fail
echo "compose interop: $failures unmet expectation(s)"
[ "$failures" -eq 0 ]
