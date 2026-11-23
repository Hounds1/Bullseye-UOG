# Core node enrollment API v2

UOG issues invitations for an approved node ID and public key. On a separate
HTTPS listener, it verifies the CSR signature and checks that the CSR public key
matches the approved fingerprint before signing a certificate. Redeeming an
invitation saves the certificate fingerprint for subsequent CCC mTLS joins.

## Configure UOG

Keep the existing CCC listener settings and configure its registration file.
Enable the HTTPS listener with the following settings.

```properties
bullseye.uog.ccc.registration-file=var/ccc-nodes.json
bullseye.uog.enrollment.enabled=true
bullseye.uog.enrollment.bind-host=10.0.0.10
bullseye.uog.enrollment.port=8443
bullseye.uog.enrollment.public-origin=https://uog.example.org:8443
bullseye.uog.enrollment.ccc-host=uog.example.org
bullseye.uog.enrollment.server-ca-file=/etc/bullseye/tls/server-ca.pem
bullseye.uog.enrollment.issuer-keystore=/etc/bullseye/tls/enrollment-issuer.p12
bullseye.uog.enrollment.issuer-alias=enrollment-ca
bullseye.uog.enrollment.issuer-password-file=/etc/bullseye/tls/enrollment-issuer.password
bullseye.uog.enrollment.admin-token-file=/etc/bullseye/tls/enrollment-admin.token
```

Use the existing [UOG JVM TLS identity](README.md#tls-stores) for HTTPS and CCC.
That identity must cover the hosts advertised for both listeners. Supply the
public CA certificates clients use to verify those listeners in `server-ca-file`.
Put the enrollment signing CA's private key and certificate chain in its PKCS#12
entry and trust its issuing chain in the UOG JVM truststore so CCC can verify the
issued Core client certificates. Store the issuer password and administrator
token in separate files readable by the UOG service account. The administrator
token is one line of 64 lowercase hexadecimal characters. Generate it with a
cryptographically secure generator, for example `openssl rand -hex 32`.

The enrollment listener is disabled by default. Distribute invitation files
through a trusted channel so a CLI can use the included public CA material to
validate the HTTPS hostname and certificate chain before sending the code.

## Issue an invitation

On the target node, prepare a key with Bullseye CLI v2 enrollment support.

```sh
bullseye enroll prepare --node-id edge-01 --output bullseye-enrollment
```

Keep the prepared files on the target node. Give the UOG administrator the
node ID and the value printed after `Public key SHA-256:` through a trusted
channel. The digest is SHA-256 of the DER-encoded `SubjectPublicKeyInfo`.

Send `POST /api/enrollment/v2/invitations` with the administrator bearer token and
a JSON object containing `nodeId` and `publicKeySha256`, a 64-character hexadecimal
digest. Node IDs for enrollment contain 1–128 ASCII letters, digits, dots,
underscores, or hyphens and start with a letter or digit. Reissuing for the same
unregistered ID replaces its previous unused invitation. Manual and registered
IDs are reserved.

```sh
umask 077
key_sha256='<64-character digest from the target node>'
printf 'Authorization: Bearer %s\n' "$(cat /etc/bullseye/tls/enrollment-admin.token)" |
  curl --fail-with-body --cacert /etc/bullseye/tls/server-ca.pem \
    --header @- --header 'Content-Type: application/json' \
    --data "$(printf '{"nodeId":"edge-01","publicKeySha256":"%s"}' "$key_sha256")" \
    --output edge-01.invite https://uog.example.org:8443/api/enrollment/v2/invitations
```

The `201 Created` response is the invitation JSON. It contains `apiVersion`
(integer `2`), `nodeId`, `publicKeySha256` (lowercase hexadecimal),
`enrollmentUrl` (the full redemption URL), `serverCaPem`, `expiresAt` (UTC ISO-8601),
and `code`. The code is an unpadded base64url string and is usable for a first
redemption for 15 minutes.

## Redeem an invitation

Redeem the invitation on the same target node using the same output path.

```sh
bullseye enroll --invite edge-01.invite --output bullseye-enrollment \
  --core-config /etc/bullseye/bullseye.properties
```

API clients create a PEM PKCS#10 CSR with the approved P-256 key and sign it with
SHA-256/ECDSA.
Save the private key, request ID, and exact CSR before the first HTTP attempt.
Send `POST /api/enrollment/v2/redeem` using the invitation code as the bearer
credential and a JSON object with `requestId` (canonical UUID string) and `csrPem`
(one PEM CSR). UOG rejects a correctly signed CSR from a different key with
`PUBLIC_KEY_MISMATCH` and keeps the invitation available to the approved key.
UOG uses the node ID from the invitation and issues a client-authentication
certificate valid for up to 90 days, limited by the signer's chain expiration.

A `200 OK` response contains `apiVersion` (`2`), `nodeId`,
`certificateChainPem` (leaf first), and a `ccc` object containing `host`,
`port`, and `serverCaPem`. Install the issued chain and existing private key
into the Core identity store and use the returned CCC address and trust
certificates in Core's connection settings.

UOG commits invitation consumption, the CCC binding, and the response together.
If the response is lost, the same code, `requestId`, and exact `csrPem` can
retrieve that response for 24 hours after commitment. This window includes
retries after a process restart and after the original invitation expires. A
different request ID or CSR cannot retrieve or change the result.

## Compatibility

Send UTF-8 requests as `application/json`. The request body limit is 16 KiB.
Responses use `application/json` and `Cache-Control: no-store`. Error objects
carry a stable `code`.

| Status | Codes |
| --- | --- |
| 400 | `INVALID_REQUEST`, `INVALID_NODE_ID`, `INVALID_PUBLIC_KEY_SHA256`, `INVALID_CSR` |
| 401 | `UNAUTHORIZED`, `INVALID_OR_EXPIRED_CODE` |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED` |
| 409 | `NODE_ID_IN_USE`, `PUBLIC_KEY_MISMATCH`, `REQUEST_CONFLICT` |
| 413 | `BODY_TOO_LARGE` |
| 503 | `TEMPORARY_UNAVAILABLE` |

Clients can consume the fields above and ignore new optional response fields.
Apply local installation settings after validating a successful response.

Upgrading to v2 retires the v1 endpoints and their unused invitations and replay
receipts. For an unregistered node with a pending v1 invitation, prepare a key and
request a new v2 invitation. Existing registered certificate bindings continue
to authorize CCC joins.
