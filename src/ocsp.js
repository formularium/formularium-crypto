import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import KeyParser from './keyparser';

const regeneratorRuntime = require('regenerator-runtime');

class OCSP {
  async createRequest(country, requestorName, certificate) {
    const ocspRequest = new pkijs.OCSPRequest();

    // add request infos like country or name of the request application
    ocspRequest.tbsRequest.requestorName = new pkijs.GeneralName({
      type: 4,
      value: new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
          new pkijs.AttributeTypeAndValue({
            type: '2.5.4.6', // Country name
            value: new asn1js.PrintableString({ value: country }),
          }),
          new pkijs.AttributeTypeAndValue({
            type: '2.5.4.3', // Common name
            value: new asn1js.BmpString({ value: requestorName }),
          }),
        ],
      }),
    });

    const parser = new KeyParser(certificate);
    const authorityKeyIdentifierValue = parser.parseAuthorityKeyIdentifier(certificate).valueHex;

    const crypto = pkijs.getCrypto();
    ocspRequest.tbsRequest.requestList = [new pkijs.Request({
      reqCert: new pkijs.CertID({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: '1.3.14.3.2.26', // SHA-1
        }),
        issuerNameHash: new asn1js.OctetString(crypto.digest({ name: 'SHA-1' }, certificate.issuer.valueBeforeDecode)),
        issuerKeyHash: new asn1js.OctetString({ valueHex: authorityKeyIdentifierValue }),
        serialNumber: new asn1js.Integer({ valueHex: certificate.serialNumber.valueBlock.valueHex }),
      }),
    })];

    const fictionBuffer = new ArrayBuffer(4);
    ocspRequest.tbsRequest.requestExtensions = [
      new pkijs.Extension({
        extnID: '1.3.6.1.5.5.7.48.1.2', // ocspNonce
        extnValue: (new asn1js.OctetString({ valueHex: fictionBuffer })).toBER(false),
      }),
    ];

    const ocspRequestData = ocspRequest.toSchema(true).toBER(false);

    return Buffer.from(new Uint8Array(ocspRequestData)).toString('base64');
  }

  async callOCSPService(url, request) {
    	return fetch(`${url}/${await request}`)
		  .then((response) => response.text().then((text) => {
			  if (text[0] != 0) {
				  throw new Error("OCSP: Certificate couldn't be validated");
				  return false;
			  }
			  return true;
      }));
  }
}

export default OCSP;
