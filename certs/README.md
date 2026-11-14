# certs/

Certificates and private keys are NOT included in this repository.

Generate your own with:

    ./scripts/generate-ssl.sh <SERVER_IP> [hostname]

The result is `certs/cert.pem` (public; give it to collectors as `-ca-file`) and `certs/key.pem` (private, mode 600, never commit it).
