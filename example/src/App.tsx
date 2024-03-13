import * as React from 'react';
import { StyleSheet, SafeAreaView, Text, ScrollView } from 'react-native';
import {
  isPlayServicesAvailable,
  prepare,
  requestToken,
} from '@pagopa/io-react-native-integrity';
import ButtonWithLoader from './components/ButtonWithLoader';

const GOOGLE_CLOUD_PROJECT_NUMBER = '1234567890';

export default function App() {
  const [isServiceAvailable, setIsServiceAvailable] =
    React.useState<boolean>(false);
  const [isPrepareLoading, setIsPrepareLoading] =
    React.useState<boolean>(false);
  const [isRequestTokenLoading, setIsRequestTokenLoading] =
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

  const prepareCallback = async () => {
    if (isServiceAvailable) {
      try {
        setIsPrepareLoading(true);
        await prepare(GOOGLE_CLOUD_PROJECT_NUMBER);
        setIsPrepareLoading(false);
      } catch (e) {
        setIsPrepareLoading(false);
        setDebugLog(`${e}`);
      }
    }
  };

  const requestTokenCallback = async () => {
    if (isServiceAvailable) {
      try {
        setIsRequestTokenLoading(true);
        const rq = await requestToken();

        setIsRequestTokenLoading(false);
        setDebugLog(rq);
      } catch (e) {
        setIsRequestTokenLoading(false);
        setDebugLog(`${e}`);
      }
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.h1}>Integrity Check Demo App</Text>
      {isServiceAvailable ? (
        <>
          <ButtonWithLoader
            title="Prepare"
            onPress={() => prepareCallback()}
            loading={isPrepareLoading}
          />
          <ButtonWithLoader
            title="Get attestation"
            onPress={() => requestTokenCallback()}
            loading={isRequestTokenLoading}
          />
        </>
      ) : null}
      <ScrollView style={styles.debug}>
        <Text>{debugLog}</Text>
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
  debug: {
    width: '100%',
    height: 300,
    position: 'absolute',
    bottom: 0,
    backgroundColor: '#eaeaea',
  },
});
