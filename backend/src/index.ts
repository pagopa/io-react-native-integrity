import express from 'express';
import { v4 as uuid } from 'uuid';
import dotenv from 'dotenv';
import verifyAttestation from './verifyAttestation';
import bodyParser from 'body-parser';
import verifyAssertion from './verifyAssertion';

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

const port = process.env.PORT || 3000;
const nonce = uuid();
let attestation: any = null;

const BUNDLE_IDENTIFIER = process.env.BUNDLE_IDENTIFIER || '';
const TEAM_IDENTIFIER = process.env.TEAM_IDENTIFIER || '';

app.get('/attest/nonce', (_, res) => {
  console.debug(`challange was requested, returning ${nonce}`);
  res.send(JSON.stringify({ nonce }));
});

app.post(`/attest/verify`, (req, res) => {
  try {
    console.debug(`verify was requested: ${JSON.stringify(req.body, null, 2)}`);
    if (nonce !== req.body.challenge) {
      throw new Error('Invalid challenge');
    }

    const result = verifyAttestation({
      attestation: Buffer.from(req.body.attestation, 'base64'),
      challenge: req.body.challenge,
      keyId: req.body.hardwareKeyTag,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      allowDevelopmentEnvironment: true,
    });

    // store the attestation for later use
    attestation = {
      keyId: req.body.hardwareKeyTag,
      publicKey: result.publicKey,
      signCount: 0,
    };

    res.json({ result: 'ok' });
  } catch (error) {
    console.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});

app.post(`/assertion/verify`, (req, res) => {
  try {
    const { hardwareKeyTag, assertion } = req.body;

    if (hardwareKeyTag === undefined || assertion === undefined) {
      throw new Error('Invalid authentication');
    }

    if (nonce !== req.body.challenge) {
      throw new Error('Invalid challenge');
    }

    if (!attestation) {
      throw new Error('No attestation found');
    }

    console.log(req.body.payload);
    const result = verifyAssertion({
      assertion: assertion,
      payload: req.body.payload,
      publicKey: attestation.publicKey,
      bundleIdentifier: BUNDLE_IDENTIFIER,
      teamIdentifier: TEAM_IDENTIFIER,
      signCount: attestation.signCount,
    });

    console.log(result);
    console.debug(`Received message: ${JSON.stringify(req.body)}`);

    res.send({ result: 'ok' });
  } catch (error) {
    console.error(error);
    res.status(401).send({ error: 'Unauthorized' });
  }
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:3000`);
});
