#!/bin/sh
# Strict single-profile TLS 1.3 server for the compose lab. Generates a disposable synthetic CA
# and leaf in tmpfs, publishes only the CA certificate, and accepts exactly one TLS group.
set -eu
# Hermetic: ignore any ambient OpenSSL config, as the Python lab does.
export OPENSSL_CONF=/dev/null
PROFILE="$1"
NAME="${PROFILE}-server"
case "$PROFILE" in
    classical) GROUP=X25519 ; ALG=RSA ;;
    hybrid) GROUP=X25519MLKEM768 ; ALG=RSA ;;
    pqc) GROUP=MLKEM768 ; ALG=ML-DSA-65 ;;
    *) echo "unknown profile: $PROFILE" >&2 ; exit 2 ;;
esac
key() {
    if [ "$ALG" = RSA ]; then
        openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1"
    else
        openssl genpkey -quiet -algorithm "$ALG" -out "$1"
    fi
}
umask 077
WORK="$(mktemp -d)"
cd "$WORK"
key ca.key
openssl req -x509 -new -key ca.key -days 2 -subj "/O=CryptoAgility Lab (synthetic)/CN=$PROFILE lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out ca.pem 2>/dev/null
key leaf.key
openssl req -new -key leaf.key -subj "/O=CryptoAgility Lab (synthetic)/CN=$NAME" -out leaf.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$NAME" > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile leaf.ext -out leaf.pem 2>/dev/null
rm -f ca.key leaf.csr
mkdir -p "/pki/$PROFILE"
umask 022
cp ca.pem "/pki/$PROFILE/ca.pem.tmp" && mv "/pki/$PROFILE/ca.pem.tmp" "/pki/$PROFILE/ca.pem"
echo "$NAME: TLS 1.3 only, group $GROUP, $ALG certificate (synthetic)"
exec openssl s_server -quiet -www -accept 4433 -tls1_3 -groups "$GROUP" \
    -cert leaf.pem -key leaf.key
