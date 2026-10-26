import * as React from 'react';
import { StyleSheet, SafeAreaView, Text, ScrollView, View } from 'react-native';
import {
  getAttestation,
  getAttestationAssertion,
  getHardwareAttestationCapabilities,
  isPlayServicesAvailable,
  prepareIntegrityToken,
  requestIntegrityToken,
  type HardwareAttestationCapabilities,
} from '@pagopa/io-react-native-integrity';
import { sign } from '@pagopa/io-react-native-crypto';
import { sha256 } from 'react-native-sha256';
import ButtonWithLoader from './components/ButtonWithLoader';
import { BACKEND_ADDRESS, GOOGLE_CLOUD_PROJECT_NUMBER } from '@env';
import uuid from 'react-native-uuid';

/**
 * Posts a JSON body to the example backend.
 */
const postToBackend = async (path: string, body: object) => {
  const result = await fetch(`${BACKEND_ADDRESS}${path}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  return result.json();
};

/**
 * Gets a single use challenge from the example backend.
 */
const getNonce = async (): Promise<string> => {
  const result = await fetch(`${BACKEND_ADDRESS}/android/nonce`);
  const { nonce } = await result.json();
  return nonce;
};

export default function AndroidApp() {
  const [isServiceAvailable, setIsServiceAvailable] =
    React.useState<boolean>(false);
  const [isPrepareLoading, setIsPrepareLoading] =
    React.useState<boolean>(false);
  const [isRequestTokenLoading, setIsRequestTokenLoading] =
    React.useState<boolean>(false);
  const [integrityToken, setIntegrityToken] = React.useState<
    string | undefined
  >();
  const [isVerifyintegrityTokenLoading, setIsVerifyintegrityTokenLoading] =
    React.useState<boolean>(false);
  const [isGetAttestationLoading, setIsGetAttestationLoading] =
    React.useState<boolean>(false);
  const [attestation, setAttestation] = React.useState<
    | { attestation: string; challenge: string; hardwareKeyTag: string }
    | undefined
  >();
  const [isVerifyAttestationLoading, setIsVerifyAttestationLoading] =
    React.useState<boolean>(false);
  const [capabilities, setCapabilities] = React.useState<
    HardwareAttestationCapabilities | undefined
  >();
  const [isVerifyAssertionLoading, setIsVerifyAssertionLoading] =
    React.useState<boolean>(false);

  const [debugLog, setDebugLog] = React.useState<string>('.. >');

  React.useEffect(() => {
    isPlayServicesAvailable()
      .then((result) => {
        setIsServiceAvailable(result);
      })
      .catch((error) => {
        setDebugLog(error);
      });
    getHardwareAttestationCapabilities()
      .then((result) => {
        setCapabilities(result);
        setDebugLog(JSON.stringify(result));
      })
      .catch((error) => {
        setDebugLog(JSON.stringify(error));
      });
  }, []);

  const prepare = async () => {
    if (isServiceAvailable) {
      try {
        setIsPrepareLoading(true);
        await prepareIntegrityToken(GOOGLE_CLOUD_PROJECT_NUMBER);
        setIsPrepareLoading(false);
      } catch (e) {
        setIsPrepareLoading(false);
        setDebugLog(JSON.stringify(e));
      }
    }
  };

  const requestToken = async () => {
    if (isServiceAvailable) {
      try {
        setIsRequestTokenLoading(true);
        const rq = await requestIntegrityToken('randomvalue');
        setIsRequestTokenLoading(false);
        setIntegrityToken(rq);
        setDebugLog(rq);
      } catch (e) {
        setIsRequestTokenLoading(false);
        setDebugLog(`${e}`);
      }
    }
  };

  const requestAttestation = async () => {
    try {
      setIsGetAttestationLoading(true);
      const hardwareKeyTag = uuid.v4().toString();
      const challenge = await getNonce();
      const att = await getAttestation(challenge, hardwareKeyTag, {
        useAttestKey: true,
      });
      setAttestation({ attestation: att, challenge, hardwareKeyTag });
      setIsGetAttestationLoading(false);
      setDebugLog(att);
    } catch (e) {
      setIsGetAttestationLoading(false);
      setDebugLog(`${e}`);
    }
  };

  const verifyToken = async () => {
    try {
      if (integrityToken === undefined) {
        setDebugLog(
          'Integrity token is undefined, please call prepare and get token first.'
        );
        return;
      }
      setIsVerifyintegrityTokenLoading(true);
      const result = await fetch(
        `${BACKEND_ADDRESS}/android/verifyIntegrityToken`,
        {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            integrityToken,
          }),
        }
      );
      const response = await result.json();
      setIsVerifyintegrityTokenLoading(false);
      setDebugLog(JSON.stringify(response));
    } catch (e) {
      setIsVerifyintegrityTokenLoading(false);
      setDebugLog(`${e}`);
    }
  };

  const verifyAttestation = async () => {
    try {
      if (attestation === undefined) {
        setDebugLog(
          'Attestation is undefined, please call get attestation first.'
        );
        return;
      }
      setIsVerifyAttestationLoading(true);
      const response = await postToBackend(
        '/android/verifyAttestation',
        attestation
      );
      setIsVerifyAttestationLoading(false);
      setDebugLog(JSON.stringify(response));
    } catch (e) {
      setIsVerifyAttestationLoading(false);
      setDebugLog(`${e}`);
    }
  };

  /**
   * Sends both the Play Integrity token, when available, and a fresh key attestation
   * along with the client data signed by the attested hardware key.
   * The backend accepts the Play Integrity verdict or, as fallback, the key attestation.
   * Play Integrity requires the "Prepare" step to be completed first.
   */
  const verifyAssertion = async () => {
    try {
      if (attestation === undefined) {
        setDebugLog(
          'Attestation is undefined, please call get and verify attestation first.'
        );
        return;
      }
      setIsVerifyAssertionLoading(true);
      const clientData = JSON.stringify({ challenge: await getNonce() });
      const clientDataHash = await sha256(clientData);
      const signature = await sign(clientData, attestation.hardwareKeyTag);
      const assertionIntegrityToken = isServiceAvailable
        ? await requestIntegrityToken(clientDataHash).catch(() => undefined)
        : undefined;
      // The backend accepts the fresh key attestation only if pinned to the attest key of the hardware key
      const attestationAssertion =
        capabilities?.isHardwareAttestationSupported &&
        capabilities.hasAttestKey
          ? await getAttestationAssertion(
              clientDataHash,
              attestation.hardwareKeyTag
            )
          : undefined;
      const response = await postToBackend('/android/verifyAssertion', {
        hardwareKeyTag: attestation.hardwareKeyTag,
        clientData,
        signature,
        integrityToken: assertionIntegrityToken,
        attestationAssertion,
      });
      setIsVerifyAssertionLoading(false);
      setDebugLog(JSON.stringify(response));
    } catch (e) {
      setIsVerifyAssertionLoading(false);
      setDebugLog(`${e}`);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollViewContentContainer}>
        <Text style={styles.h1}>Integrity Check Demo App</Text>
        {isServiceAvailable ? (
          <>
            <Text style={styles.h2}>Play Integrity Standard Request</Text>
            <ButtonWithLoader
              title="Prepare"
              onPress={() => prepare()}
              loading={isPrepareLoading}
            />
            <View style={styles.spacer} />
            <ButtonWithLoader
              title="Get token"
              onPress={() => requestToken()}
              loading={isRequestTokenLoading}
            />
            <View style={styles.spacer} />
            <ButtonWithLoader
              title="Verify Token"
              onPress={() => verifyToken()}
              loading={isVerifyintegrityTokenLoading}
            />
            <View style={styles.spacer} />
          </>
        ) : null}
        {capabilities?.isHardwareAttestationSupported ? (
          <>
            <Text style={styles.h2}>Key Attestation</Text>
            <ButtonWithLoader
              title="Get attestation"
              onPress={() => requestAttestation()}
              loading={isGetAttestationLoading}
            />
            <View style={styles.spacer} />
            <ButtonWithLoader
              title="Verify attestation"
              onPress={() => verifyAttestation()}
              loading={isVerifyAttestationLoading}
            />
            <View style={styles.spacer} />
            <Text style={styles.h2}>Integrity Assertion</Text>
            <ButtonWithLoader
              title="Verify assertion"
              onPress={() => verifyAssertion()}
              loading={isVerifyAssertionLoading}
            />
            <View style={styles.spacer} />
          </>
        ) : null}
        <>
          <Text>{debugLog}</Text>
        </>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
  },
  scrollViewContentContainer: {
    justifyContent: 'center',
    alignItems: 'center',
    flexGrow: 1,
    padding: 10,
  },
  h1: {
    fontWeight: 'bold',
    fontSize: 32,
    textAlign: 'center',
    marginTop: 16,
    marginBottom: 16,
  },
  h2: {
    fontWeight: 'bold',
    fontSize: 16,
    textAlign: 'center',
    marginTop: 16,
    marginBottom: 16,
  },
  spacer: {
    height: 8,
  },
  debug: {
    width: '100%',
    height: 300,
    position: 'absolute',
    bottom: 0,
    backgroundColor: '#eaeaea',
  },
});
