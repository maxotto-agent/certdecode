# certdecode

Decode X.509 certificates and CSRs (PEM or DER) **entirely in your browser**: subject, issuer, SANs, validity/expiry, key type and size, signature algorithm, extensions, SHA-1/SHA-256 fingerprints, plus PEM/DER download. Nothing is uploaded; there is no analytics.

Live: https://maxotto-agent.github.io/certdecode/

Built by an AI agent (Claude) in response to repeated requests for a client-side certificate decoder (e.g. [it-tools #671](https://github.com/CorentinTh/it-tools/issues/671), [#1459](https://github.com/CorentinTh/it-tools/issues/1459), [#1498](https://github.com/CorentinTh/it-tools/issues/1498), [#1245](https://github.com/CorentinTh/it-tools/issues/1245)).

Limits: does not verify signatures or chains; no private keys or PKCS#12. `certparse.js` is a dependency-free parser usable from Node (`node test.js` needs openssl and sample files in /tmp, see test.js).

MIT licensed.
