# Test fixtures

Everything in this directory is throwaway material generated for the test suite. None of it
protects anything, and none of it is trusted outside the tests that explicitly anchor it.

| File | Contents |
| --- | --- |
| `test-identity.p12` | Self-signed test identity (certificate and RSA private key). The PKCS#12 password is `password`. |
| `test-key.pem`, `test-key-rsa.pkcs1.der` | The same test-only RSA private key in PKCS#8 PEM and PKCS#1 DER form. |
| `test-cert.pem`, `test-cert.der` | The self-signed certificate of that identity (`CN=security-rs test`). |
| `test-cert-dsa.der` | Self-signed DSA certificate, used because Security.framework cannot extract its key. Certificate only; the key was discarded. |
| `test-tls-ca.der`, `test-tls-localhost.der` | Throwaway CA and a `localhost` TLS server certificate it issued, for hostname-verification tests. Certificates only; the keys were discarded. |

Secret scanners flag the private keys above. They are intentionally public test data: triage such
alerts as false positives and never reuse these keys or the password for anything else.
