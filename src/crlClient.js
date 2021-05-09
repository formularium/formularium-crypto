import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

require('isomorphic-fetch');

class CRLClient {
  fetchCRL(crlURL) {
    // fetch CRL
    return fetch(crlURL)
      .then((response) => {
        if (!response.ok) {
          throw new Error('CRL: Network response was not ok');
        }
        // convert to buffer
        return response.arrayBuffer();
      })
      .then((buffer) => {
        // convert to asn1 and load in pkijs
        const asn1 = asn1js.fromBER(buffer);
        const crlSimpl = new pkijs.CertificateRevocationList({
          schema: asn1.result,
        });
        return crlSimpl;
      });
  }
}

export default CRLClient;
