# @pagopa/io-react-native-integrity

![CI workflow](https://github.com/pagopa/io-react-native-integrity/actions/workflows/ci.yml/badge.svg)
![Publish workflow](https://github.com/pagopa/io-react-native-integrity/actions/workflows/publish.yml/badge.svg)
![Code QL workflow](https://github.com/pagopa/io-react-native-integrity/actions/workflows/github-code-scanning/codeql/badge.svg)

React Native interfaces for managing secure storage in iOS and Android.

## Installation

```sh
npm install @pagopa/io-react-native-integrity
# or
yarn add @pagopa/io-react-native-integrity
```

## Android

The Android implementation is based on the [Play Integrity API](https://developer.android.com/google/play/integrity/overview) which provides a set of APIs to help developers protect their apps from tampering. The usage of this API also requires a backend server to verify the integrity token generated by the app.
An example is provided in the [example/backend](example/backend) directory. Make sure to follow the instructions in the [example/README.md](example/README.md) file to set up the backend server and update the `.env` file with the correct values to test the library.
The flow provided by the library is the [standard one](https://developer.android.com/google/play/integrity/standard?hl=it).
The main difference from iOS is that Android relies on Google Play Services and a remote service provided by Google.

A [Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) can be generated using the `getAttestation` method.
During key attestation, a key pair is generated along with its certificate chain hich can be used to verify the properties of that key pair.
If the device supports hardware-level key attestation, the root certificate of the chain is signed using an attestation root key protected by the device's hardware-backed keystore.

### `isPlayServicesAvailable`

Returns a boolean value indicating whether the Play Services are available on the device or not.

```ts
try {
  const isServiceAvailable = await isPlayServicesAvailable();
  if (isServiceAvailable) {
    // Proceed with the following steps
  } else {
    // Return an error message
  }
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `prepareIntegrityToken`

Prepares the integrity token provider before obtaining the integrity verdict.
This function can be called well before the moment an integrity verdict is needed, for example when starting the application.
It can also be called time to time to refresh it.
A Google Cloud Project Number is required to use this API. Follow the official documentation provided by Google [here](https://developer.android.com/google/play/integrity/setup).

```ts
try {
  await prepareIntegrityToken(GOOGLE_CLOUD_PROJECT_NUMBER);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `requestIntegrityToken`

Requests an integrity token which is then attached to the request to be protected.
It must be called AFTER `prepareIntegrityToken` has been called and resolved successfully.
The token is a base64 encoded string.

```ts
try {
  const token = await requestIntegrityToken();
  console.log(token);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `getAttestation`

Returns a [Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) which can later be verified by the backend server.

```ts
try {
  const attestation = await getAttestation(challenge, hardwareKeyTag);
  console.log(attestation);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

## iOS

The iOS implementation is based on the [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) which is availabe from iOS 14.0 onwards.
It's a framework provided by Apple for iOS that allows apps to verify if a specific device has been used to perform a particular action, without revealing the identity of the device itself or its owner. It is useful for preventing abuse by users who try to manipulate the system or use the app fraudulently.
This implementation doesn't relay on any remote service.

### `generateHardwareKey`

Generates a hardware key that can be used into the attestation process when calling `getAttestaiton`.

```ts
try {
  const key = await generateHardwareKey();
  console.log(key);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `getAttestation`

Generates an attestation for the given challenge and hardware key. The hardware key generated at the previous step can be used here.

```ts
try {
  const attestation = await getAttestation(challenge, key);
  console.log(attestation);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `generateHardwareSignatureWithAssertion`

Generates a signature for the given client data given an hardware key. The hardware key generate at the previous step can be used here.

```ts
try {
  const signature = await generateHardwareSignatureWithAssertion(
    clientData,
    key
  );
  console.log(signature);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

### `decodeAttestation`

Decodes the CBOR encoded attestation returned by the `getAttestation` method. Returns an object containing `signature` and `authenticatorData` as base64 encoded strings.

```ts
try {
  const decoded = await decodeAttestation(attestation);
  console.log(decoded);
} catch (e) {
  const error = e as IntegrityError;
  console.log(JSON.stringify(error));
}
```

## Types

|      TypeName      | Description                                                                                                                       |
| :----------------: | --------------------------------------------------------------------------------------------------------------------------------- |
| SecureStorageError | This type defines the error returned by the secure storage engine and includes an error code and an additional information object |

## Error Codes

|                 TypeName                 |  Platform   | Description                                                                                          |
| :--------------------------------------: | :---------: | ---------------------------------------------------------------------------------------------------- |
| WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT |   Android   | A wrong value for `GOOGLE_CLOUD_PROJECT_NUMBER` has been provided to `prepareIntegrityToken`         |
|              PREPARE_FAILED              |   Android   | A critical error occurred during the `prepareIntegrityToken` operation                               |
|            PREPARE_NOT_CALLED            |   Android   | The `requestIntegrityToken` has been called without calling `prepareIntegrityToken` beforehand       |
|           REQUEST_TOKEN_FAILED           |   Android   | A critical error occurred during the `requestIntegrityToken` operation                               |
|        REQUEST_ATTESTATION_FAILED        |   Android   | A critical error occurred during the `getAttestation` operation                                      |
|        KEY_IS_NOT_HARDWARE_BACKED        |   Android   | The device doesn't support hardware backed keys, thus it cannot be trusted                           |
|            KEY_ALREADY_EXISTS            |   Android   | The provided `hardwareKeyTag` already has an associated key                                          |
|         KEYSTORE_NOT_INITIALIZED         |   Android   | A critical error occurred while initializing the keystore service                                    |
|          GENERATION_KEY_FAILED           |     iOS     | A critical error occurred during the `generateHardwareKey` operation                                 |
|            ATTESTATION_ERROR             |     iOS     | A critical error occurred during the `getAttestation` operation                                      |
|         UNSUPPORTED_IOS_VERSION          |     iOS     | The device has a version of iOS that doesn't support the DeviceCheck App Attestation Service (<14.0) |
|             CHALLENGE_ERROR              |     iOS     | An error occured while encoding the provided challenge to `getAttestation`                           |
|        CLIENT_DATA_ENCODING_ERROR        |     iOS     | An error occured while encoding the provided client data to `generateHardwareSignatureWithAssertion` |
|       GENERATION_ASSERTION_FAILED        |     iOS     | A critical error occurred during the `generateHardwareSignatureWithAssertion` operation              |
|            UNSUPPORTED_DEVICE            | iOS/Android | The device doesn't support the requested functionality                                               |

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)

```

```
