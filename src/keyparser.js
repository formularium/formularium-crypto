import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import * as base64array from 'base64-arraybuffer';
import { CertificateChainValidationEngine } from 'pkijs';
import CRLClient from './crlClient';

const regeneratorRuntime = require('regenerator-runtime');

class KeyParser {
  constructor(certificates) {
    this.certificates = certificates;
  }

  static fromx509(certificate) {
    const x5chain = [];
    for (const i in certificate.x5c) {
      x5chain.push(new pkijs.Certificate({ schema: asn1js.fromBER(base64array.decode(certificate.x5c[i])).result }));
    }
    return new KeyParser(x5chain);
  }

  static decodeCert(pem) {
    if (typeof pem !== 'string') {
      throw new Error('Expected PEM as string');
    }

    // Load certificate in PEM encoding (base64 encoded DER)
    const b64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');

    // Now that we have decoded the cert it's now in DER-encoding
    const der = Buffer(b64, 'base64');

    // And massage the cert into a BER encoded one
    const ber = new Uint8Array(der).buffer;

    // And now Asn1js can decode things \o/
    const asn1 = asn1js.fromBER(ber);

    return new pkijs.Certificate({ schema: asn1.result });
  }

  async verify(root_cert) {
    const crls = [];
    const crlc = new CRLClient();
    // fetch all crls
    const urls = this.parseCRLURL();
    for (const u in urls) {
      crls.push(await crlc.fetchCRL(urls[u].url));
    }
    // decode the root cert
    root_cert = [KeyParser.decodeCert(root_cert)];
    // run verification
    const certChainVerificationEngine = new CertificateChainValidationEngine({
      trustedCerts: root_cert,
      certs: this.certificates,
      crls,
    });
    return await certChainVerificationEngine.verify();
  }

  parseCRLURL() {
    const distributionPoints = [];

    for (const c in this.certificates) {
      const certificate = this.certificates[c];

      for (let i = 0; i < certificate.extensions.length; i++) {
      // 2.5.29.31 stands for CRLs
        if (certificate.extensions[i].extnID === '2.5.29.31') {
          for (const point in certificate.extensions[i].parsedValue
            .distributionPoints) {
            for (const url in certificate.extensions[i].parsedValue
              .distributionPoints[point].distributionPoint) {
              distributionPoints.push({
                url:
              certificate.extensions[i].parsedValue.distributionPoints[point]
                .distributionPoint[url].value,
                type:
              certificate.extensions[i].parsedValue.distributionPoints[point]
                .distributionPoint[url].type,
              });
            }
          }
        }
      }
    }

    return distributionPoints;
  }

  getPublicKey() {
    const asn1PublicKey = asn1js.fromBER(
      this.certificates[this.certificates.length - 1].subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex,
    );
    return new pkijs.RSAPublicKey({ schema: asn1PublicKey.result });
  }

  parseCertificateAuthorityInformationAccess() {
    const information_access_urls = [];

    for (const c in this.certificates) {
      const certificate = this.certificates[c];
      for (let i = 0; i < certificate.extensions.length; i++) {
        // console.log(certificate.extensions[i]);
        // 1.3.6.1.5.5.7.1.1 stands for Certificate Authority Information Access
        if (certificate.extensions[i].extnID === '1.3.6.1.5.5.7.1.1') {
          for (const url in certificate.extensions[i].parsedValue
            .accessDescriptions) {
            information_access_urls.push({
              url:
                certificate.extensions[i].parsedValue.accessDescriptions[url]
                  .accessLocation.value,
              type:
                certificate.extensions[i].parsedValue.accessDescriptions[url]
                  .accessLocation.type,
              accessMethod:
                certificate.extensions[i].parsedValue.accessDescriptions[url]
                  .accessMethod,
            });
          }
        }
      }
    }

    return information_access_urls;
  }

  parseAuthorityKeyIdentifier(certificate) {
    for (let i = 0; i < certificate.extensions.length; i++) {
      // 2.5.29.35 stands for AuthorityKeyIdentifier
      if (certificate.extensions[i].extnID === '2.5.29.35') {
        return {
          valueHex:
            certificate.extensions[i].parsedValue.keyIdentifier.valueBlock
              .valueHex,
        };
      }
    }
  }

  parseOCSPURL() {
    const distributionEndpoints = this.parseCertificateAuthorityInformationAccess();
    for (const c in distributionEndpoints) {
      if (distributionEndpoints[c].accessMethod === '1.3.6.1.5.5.7.48.1') {
        return distributionEndpoints[c].url;
      }
    }
    return null;
  }
}

export default KeyParser;
