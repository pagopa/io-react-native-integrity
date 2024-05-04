import * as React from 'react';
import { StyleSheet, SafeAreaView, Text, ScrollView } from 'react-native';
import {
  generateHardwareKey,
  getAttestation,
  isAttestationServiceAvailable,
  generateHardwareSignatureWithAssertion,
  type IntegrityError,
} from '@pagopa/io-react-native-integrity';
import { BACKEND_ADDRESS } from '@env';
import ButtonWithLoader from './components/ButtonWithLoader';

// this is a mocked jwk for ephimeral public key, in a production
// environment the ephimeral key must be generated by the client
// every time a WTE must be required
const jwk = {
  crv: 'P-256',
  kty: 'EC',
  x: '4HNptI-xr2pjyRJKGMnz4WmdnQD_uJSq4R95Nj98b44',
  y: 'LIZnSB39vFJhYgS3k7jXE4r3-CoGFQwZtPBIRqpNlrg',
  kid: 'vbeXJksM45xphtANnCiG6mCyuU4jfGNzopGuKvogg9c',
};

export default function App() {
  const [challenge, setChallenge] = React.useState<string>('');
  const [hardwareKeyTag, setHardwareKeyTag] = React.useState<
    string | undefined
  >('');
  const [attestation, setAttestation] = React.useState<string | undefined>('');
  const [assertion, setAssertion] = React.useState<string | undefined>('');
  const [hsWithAssertion, setHsWithAssertion] = React.useState<
    string | undefined
  >('');
  const [isServiceAvailable, setIsServiceAvailable] =
    React.useState<boolean>(false);
  const [debugLog, setDebugLog] = React.useState<string>('.. >');

  React.useEffect(() => {
    isAttestationServiceAvailable()
      .then((result) => {
        setIsServiceAvailable(result);
      })
      .catch((error: IntegrityError) => {
        setDebugLog(error.message);
      });
  }, []);

  const getHardwareKey = async () => {
    setHardwareKeyTag(undefined);
    const hardwareKey = await generateHardwareKey();
    setHardwareKeyTag(hardwareKey);
    setDebugLog(hardwareKey);
  };

  const postRequest = async (endpoint: string, body: object) => {
    console.log(BACKEND_ADDRESS);
    const response = await fetch(`${BACKEND_ADDRESS}/${endpoint}`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    return response;
  };

  const getChallengeFromServer = async () => {
    // contact server run on local at port 3000 to get
    // the challenge to be used for the attestation
    try {
      const response = await fetch(`${BACKEND_ADDRESS}/attest/nonce`);
      const result = await response.json();
      return result.nonce;
    } catch {
      return '';
    }
  };

  const requestAttestation = async () => {
    setAttestation(undefined);
    if (hardwareKeyTag) {
      // get challenge from server
      const nonce = await getChallengeFromServer();
      setChallenge(nonce);
      getAttestation(nonce, hardwareKeyTag)
        .then((result) => {
          setAttestation(result);
          setDebugLog(result);
        })
        .catch((error: IntegrityError) => {
          setDebugLog(error.message + ':' + JSON.stringify(error.userInfo));
          setAttestation('');
        });
    }
  };

  const verifyAttestation = async () => {
    // verify attestation on the server with POST
    // and body of challenge, attestation and keyId
    const result = await postRequest('attest/verify', {
      challenge: challenge,
      attestation: attestation,
      hardwareKeyTag: hardwareKeyTag,
    });
    const response = await result.json();
    setDebugLog(JSON.stringify(response));
  };

  const verifyAssertion = async () => {
    // verify attestation on the server with POST
    // and body of challenge, attestation and keyId

    const result = await postRequest('assertion/verify', {
      challenge: challenge,
      assertion: assertion,
      hardwareKeyTag: hardwareKeyTag,
      payload: JSON.stringify({ challenge: challenge, jwk: jwk }),
    });
    const response = await result.json();
    setDebugLog(JSON.stringify(response));
  };

  const getHardwareSignatureWithAssertion = async () => {
    const clientData = {
      challenge: challenge,
      jwk: jwk,
    };
    // Between Android and iOS there is a difference for the generation of hardwareSignature
    // and assertion as on iOS both are generated directly from the SDK via generateAssertion
    // while on Android the hardwareSignature must be generated via the signature functions and
    // the assertion must be retrieved from the backend via an integrityToken.
    if (hardwareKeyTag) {
      const result = await generateHardwareSignatureWithAssertion(
        JSON.stringify(clientData),
        hardwareKeyTag
      );
      setHsWithAssertion(result);
      setDebugLog(result);
      setAssertion(result);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.h1}>Integrity Check Demo App</Text>
      {isServiceAvailable ? (
        <>
          <ButtonWithLoader
            title="Generate Hardware Key"
            onPress={() => getHardwareKey()}
            loading={hardwareKeyTag === undefined}
          />
          <ButtonWithLoader
            title="Get attestation"
            onPress={() => requestAttestation()}
            loading={attestation === undefined}
          />
          <ButtonWithLoader
            title="Generate HS and Assertion"
            onPress={() => getHardwareSignatureWithAssertion()}
            loading={hsWithAssertion === undefined}
          />
          <ButtonWithLoader
            title="VerifyAttestation"
            onPress={() => verifyAttestation()}
            loading={false}
          />
          <ButtonWithLoader
            title="VerifyAssertion"
            onPress={() => verifyAssertion()}
            loading={false}
          />
        </>
      ) : (
        <Text style={styles.h2}>{'Attestation Service is not available'}</Text>
      )}
      <ScrollView style={styles.debug}>
        <Text style={styles.h2}>{debugLog}</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
  },
  h1: {
    fontWeight: 'bold',
    fontSize: 32,
    textAlign: 'center',
    marginTop: 50,
    marginBottom: 50,
  },
  h2: {
    fontWeight: 'bold',
    fontSize: 14,
    textAlign: 'center',
    marginTop: 50,
    marginBottom: 50,
  },
  debug: {
    width: '100%',
    height: 300,
    position: 'absolute',
    bottom: 0,
    backgroundColor: '#eaeaea',
  },
});
