# Core node enrollment API v1

UOG issues node-specific invitations and redeems them on a separate HTTPS
listener. Redeeming an invitation saves the certificate fingerprint in the CCC
registration store. CCC can use that binding on the next mTLS join.

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

Send `POST /api/enrollment/v1/invitations` with the administrator bearer token and
a JSON object containing `nodeId`. Node IDs for enrollment contain 1–128 ASCII
letters, digits, dots, underscores, or hyphens and start with a letter or digit.
UOG reserves the ID for this invitation. Reissuing for the same unregistered
ID replaces its previous unused invitation. Manual and registered IDs are
reserved.

```sh
umask 077
printf 'Authorization: Bearer %s\n' "$(cat /etc/bullseye/tls/enrollment-admin.token)" |
  curl --fail-with-body --cacert /etc/bullseye/tls/server-ca.pem \
    --header @- --header 'Content-Type: application/json' \
    --data '{"nodeId":"edge-01"}' --output edge-01.invite \
    https://uog.example.org:8443/api/enrollment/v1/invitations
```

The `201 Created` response is the invitation JSON. It contains `apiVersion`
(integer `1`), `nodeId`, `enrollmentUrl` (the full redemption URL), `serverCaPem`,
`expiresAt` (UTC ISO-8601), and `code`. The code is an unpadded base64url string
and is usable for a first redemption for 15 minutes.

## Redeem an invitation

Generate a P-256 key locally and create a PEM PKCS#10 CSR signed with
SHA-256/ECDSA. Save the private key, request ID, and exact CSR before the first
HTTP attempt. Send `POST /api/enrollment/v1/redeem` using the invitation code as
the bearer credential and a JSON object with `requestId` (canonical UUID
string) and `csrPem` (one PEM CSR). The UOG assigns the node ID from the
invitation. It issues a client-authentication certificate valid for up to 90 days,
limited by the signer's chain expiration.

A `200 OK` response contains `apiVersion` (`1`), `nodeId`,
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
| 400 | `INVALID_REQUEST`, `INVALID_NODE_ID`, `INVALID_CSR` |
| 401 | `UNAUTHORIZED`, `INVALID_OR_EXPIRED_CODE` |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED` |
| 409 | `NODE_ID_IN_USE`, `REQUEST_CONFLICT` |
| 413 | `BODY_TOO_LARGE` |
| 503 | `TEMPORARY_UNAVAILABLE` |

A v1 client can consume the fields above and ignore new optional response
fields. A missing v1 endpoint means enrollment is unavailable at that address.
Apply local installation settings only after a validated success response. UOG
uses the same v1 endpoints and existing fields across compatible releases.
