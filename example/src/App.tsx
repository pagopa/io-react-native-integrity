import * as React from 'react';
import { StyleSheet, SafeAreaView, Text, ScrollView } from 'react-native';
import {
  getAttestation,
  isPlayServicesAvailable,
  prepareIntegrityToken,
  requestIntegrityToken,
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
  const [isGetAttestationLoading, setIsGetAttestationLoading] =
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
        await prepareIntegrityToken(GOOGLE_CLOUD_PROJECT_NUMBER);
        setIsPrepareLoading(false);
      } catch (e) {
        setIsPrepareLoading(false);
        setDebugLog(JSON.stringify(e));
      }
    }
  };

  const requestTokenCallback = async () => {
    if (isServiceAvailable) {
      try {
        setIsRequestTokenLoading(true);
        const rq = await requestIntegrityToken(
          'lW1DCr5p4nLA2JkYU7BRYzCCByQplBcrXpEMNHanu8OE43sHpRqi1SAnUQTSaFVyYOh4GrXfTJuBIIoriwbhGizYWeHYxOWh2cGs0pLcXUROXYAbnQIYPwJBZQ2V1lW1DCr5p4nLA2JkYU7BRYzCCByQi28plBcrXpEMNHanu8OE43sHpRqi1SAnUQTSaFVyYOh4GrXfTJuBIIoriwbhGizYWeHYxOWh2cGs0pLcXUROXYAbnQIYPwJBZQ2V1lW1DCr5p4nLA2JkYU7BRYzCCByQi28plBcrXpEMNHanu8OE43sHpRqi1SAnUQTSaFVyYOh4GrXfTJuBIIoriwbhGizYWeHYxOWh2cGs0pLcXUROXYAbnQIYPwJBZQ2V1lW1DCr5p4nLA2JkYU7BRYzCCByQi28plBcrXpEMNHanu8OE43sHpRqi1SAnUQTSaFVyYOh4GrXfTJuBIIoriwbhGizYWeHYxOWh2cGs0pLcXUROXYAbn'
        );

        setIsRequestTokenLoading(false);
        setDebugLog(rq);
      } catch (e) {
        setIsRequestTokenLoading(false);
        setDebugLog(`${e}`);
      }
    }
  };

  const getAttestationCallback = async () => {
    try {
      setIsGetAttestationLoading(true);
      const att = await getAttestation(
        'lW1DCr5p4nLA2JkYU7BRYzCCByQi28plBcrXpEMNHanu8OE43sHpRqi1SAnUQTSaFVyYOh4GrXfTJuBIIoriwbhGizYWeHYxOWh2cGs0pLcXUROXYAbnQIYPwJBZQ2V1'
      );
      setIsGetAttestationLoading(false);
      setDebugLog(att);
    } catch (e) {
      setIsGetAttestationLoading(false);
      setDebugLog(`${e}`);
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
            title="Get token"
            onPress={() => requestTokenCallback()}
            loading={isRequestTokenLoading}
          />
          <ButtonWithLoader
            title="Get attestation"
            onPress={() => getAttestationCallback()}
            loading={isGetAttestationLoading}
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
