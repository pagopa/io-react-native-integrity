import * as React from 'react';
import { StyleSheet, SafeAreaView, Text, ScrollView, View } from 'react-native';
import {
  getAttestation,
  isPlayServicesAvailable,
  prepareIntegrityToken,
  requestIntegrityToken,
} from '@pagopa/io-react-native-integrity';
import ButtonWithLoader from './components/ButtonWithLoader';
import { BACKEND_ADDRESS, GOOGLE_CLOUD_PROJECT_NUMBER } from '@env';
import uuid from 'react-native-uuid';

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
  const [attestation, setAttestation] = React.useState<string | undefined>();
  const [isVerifyAttestationLoading, setIsVerifyAttestationLoading] =
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
      const hardwareKeyTag = uuid.v4();
      const att = await getAttestation('randomvalue', hardwareKeyTag);
      setAttestation(att);
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
      const result = await fetch(
        `${BACKEND_ADDRESS}/android/verifyAttestation`,
        {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            attestation,
          }),
        }
      );
      const response = await result.json();
      setIsVerifyAttestationLoading(false);
      setDebugLog(JSON.stringify(response));
    } catch (e) {
      setIsVerifyAttestationLoading(false);
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
