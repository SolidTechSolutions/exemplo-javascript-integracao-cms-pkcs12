'use strict';

/**
 * [EN]    CAdES (CMS) signing example using a PKCS#12 certificate pre-imported into SolidSign cache.
 *         Start: node src/index.js
 *         Batch: POST http://localhost:8091/api/cms/sign-pkcs12
 *         Form:  POST http://localhost:8091/api/cms/sign/form
 *
 * [PT-BR] Exemplo de assinatura CAdES (CMS) com certificado PKCS#12 pré-importado na cache do SolidSign.
 *         Iniciar: node src/index.js
 *         Lote:    POST http://localhost:8091/api/cms/sign-pkcs12
 *         Form:    POST http://localhost:8091/api/cms/sign/form
 */

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const CmsPkcs12Service = require('./service');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const service = new CmsPkcs12Service();

app.post('/api/cms/sign-pkcs12', async (req, res) => {
  const inputPath = process.env.SOLIDSIGN_BATCH_INPUT_PATH || '';
  const outputPath = process.env.SOLIDSIGN_BATCH_OUTPUT_PATH || '';
  const certId = process.env.SOLIDSIGN_CERT_ID || '';

  if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isDirectory()) {
    return res.status(400).json({ error: `Invalid input path: ${inputPath}` });
  }

  const allFiles = fs.readdirSync(inputPath)
    .filter(f => fs.statSync(path.join(inputPath, f)).isFile())
    .map(f => path.join(inputPath, f));

  if (allFiles.length === 0) return res.json({ message: `No files found in ${inputPath}` });

  const resultPath = await service.signPkcs12(allFiles, certId, outputPath);
  if (resultPath) return res.json({ message: `Processing completed! ZIP generated at: ${resultPath}` });
  return res.status(500).json({ error: 'Processing failed. Check logs.' });
});

app.post('/api/cms/sign/form',
  upload.single('document') && upload.fields([{ name: 'document' }]),
  upload.fields([{ name: 'document' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const { authorization, baseUrl, pfxCode, profile, hashAlgorithm, signaturePackaging, policyVersion } = req.body;

    const zipBuffer = await service.signPkcs12Form({
      authorization, baseUrl, pfxCode, documents,
      profile, hashAlgorithm, signaturePackaging, policyVersion,
    });

    if (zipBuffer) {
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename=signed_cms.zip');
      return res.send(zipBuffer);
    }
    return res.status(500).json({ error: 'Processing failed. Check logs.' });
  }
);

const PORT = process.env.PORT || 8091;
app.listen(PORT, () => console.info(`SolidSign CMS PKCS12 example running on port ${PORT}`));
