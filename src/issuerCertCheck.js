import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { arrayBufferToString, bufferToHexCodes, toBase64 } from 'pvutils';
import * as base64array from 'base64-arraybuffer';

require('isomorphic-fetch');

class IssuerCertCheck {
  constructor(certificate) {
    this.certificate = certificate;
  }

  getCertFromEndpoints(endpoints) {
    for (const c in endpoints) {
      if (endpoints[c].accessMethod === '1.3.6.1.5.5.7.48.2') {
        return this.fetchIssuerCert(endpoints[c].url);
      }
    }
  }

  fetchIssuerCert(certURL) {
    // fetch CRL
    return fetch(certURL)
      .then((response) => {
        if (!response.ok) {
          throw new Error('Issuer Cert: Network response was not ok');
        }
        // convert to buffer
        return response;
      })
      .then((buffer) => {
        // convert to asn1 and load in pkijs
        const asn1 = asn1js.fromBER(base64array.decode(buffer));
        const cert = new pkijs.Certificate({
          schema: asn1.result,
        });
        return cert;
      });
  }
}

export default IssuerCertCheck;
