'use strict';

/**
 * [EN]    CAdES (CMS) signing service using a PKCS#12 certificate pre-imported into the cache.
 *         Calls the SolidSign API endpoint: POST /solidsign/dsig/cms/sign-pkcs12
 *
 * [PT-BR] Serviço de assinatura CAdES (CMS) utilizando certificado PKCS#12 pré-importado na cache.
 *         Chama o endpoint da API SolidSign: POST /solidsign/dsig/cms/sign-pkcs12
 */

const axios = require('axios');
const FormData = require('form-data');
const JSZip = require('jszip');
const fs = require('fs');
const path = require('path');

class CmsPkcs12Service {
  constructor() {
    this.baseUrl = (process.env.SOLIDSIGN_API_BASE_URL || '').replace(/\/$/, '');
    this.authorization = process.env.SOLIDSIGN_API_AUTHORIZATION || '';
    this.profile = process.env.SOLIDSIGN_SIG_PROFILE || 'ADRB';
    this.hashAlgorithm = process.env.SOLIDSIGN_SIG_HASH_ALGORITHM || 'SHA256';
    this.signaturePackaging = process.env.SOLIDSIGN_SIG_PACKAGING || 'ENVELOPING';
    this.policyVersion = process.env.SOLIDSIGN_SIG_POLICY_VERSION || '';
  }

  async signPkcs12(files, certId, outputDir) {
    console.info(`Starting CAdES PKCS12 signing for ${files.length} file(s) using certId=${certId}.`);
    const signUrl = `${this.baseUrl}/solidsign/dsig/cms/sign-pkcs12`;
    const form = new FormData();

    for (let i = 0; i < files.length; i++) {
      form.append(`document[${i}]`, fs.createReadStream(files[i]), { filename: path.basename(files[i]) });
    }

    form.append('pfxCode', certId);
    form.append('profile', this.profile);
    form.append('hashAlgorithm', this.hashAlgorithm);
    form.append('signaturePackaging', this.signaturePackaging);
    if (this.policyVersion) form.append('policyVersion', this.policyVersion);

    try {
      const resp = await axios.post(signUrl, form, {
        headers: { Authorization: this.authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      const zipBuffer = await this._downloadAndZip(resp.data, files.map(f => path.basename(f)), this.authorization);
      fs.mkdirSync(outputDir, { recursive: true });
      const outPath = path.join(outputDir, `signed_cms_pkcs12_${Date.now()}.zip`);
      fs.writeFileSync(outPath, zipBuffer);
      console.info(`CAdES PKCS12 signing complete. Output: ${outPath}`);
      return outPath;
    } catch (err) {
      this._logError('CAdES PKCS12 signing', err);
      return null;
    }
  }

  async signPkcs12Form({ authorization, baseUrl, pfxCode, documents,
    profile, hashAlgorithm, signaturePackaging, policyVersion }) {

    console.info(`CAdES PKCS12 form signing for ${documents.length} file(s).`);
    const signUrl = `${baseUrl.replace(/\/$/, '')}/solidsign/dsig/cms/sign-pkcs12`;
    const form = new FormData();

    for (let i = 0; i < documents.length; i++) {
      form.append(`document[${i}]`, documents[i].buffer, { filename: documents[i].originalname });
    }

    form.append('pfxCode', pfxCode);
    if (profile)            form.append('profile', profile);
    if (hashAlgorithm)      form.append('hashAlgorithm', hashAlgorithm);
    if (signaturePackaging) form.append('signaturePackaging', signaturePackaging);
    if (policyVersion)      form.append('policyVersion', policyVersion);

    try {
      const resp = await axios.post(signUrl, form, {
        headers: { Authorization: authorization, ...form.getHeaders() },
        timeout: 120000,
      });
      return this._downloadAndZip(resp.data, documents.map(d => d.originalname), authorization);
    } catch (err) {
      this._logError('CAdES PKCS12 form signing', err);
      return null;
    }
  }

  async _downloadAndZip(signResponse, originalNames, auth) {
    const zip = new JSZip();
    await Promise.all((signResponse.documents || []).map(async (doc, i) => {
      const selfLink = doc._links?.self || (doc.links || []).find(l => l.rel === 'self');
      if (!selfLink) return;
      const r = await axios.get(selfLink.href, {
        headers: { Authorization: auth },
        responseType: 'arraybuffer',
        timeout: 120000,
      });
      if (r.status === 200) zip.file(`signed_${originalNames[i]}`, r.data);
    }));
    return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  }

  _logError(context, err) {
    if (err.response) {
      console.error(`SolidSign API error ${err.response.status} during ${context}: ${JSON.stringify(err.response.data)}`);
    } else {
      console.error(`Unexpected error during ${context}: ${err.message}`);
    }
  }
}

module.exports = CmsPkcs12Service;
