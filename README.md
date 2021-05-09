# formularium-crypto
> We roll our own security! 🤡 🤡 🤡 

No, seriously, as there is currently no implementation of jwk x509 chain validation available (including verification against certificate revocation lists, OCSP, …)
We implemented it on our own. It's based on PKI.js, so we didn't actually start from scratch. 
### Why?
formularium implements the FIT-Connect standard. It requires us to validate the JWK cert chains we use in the browser for encryption.