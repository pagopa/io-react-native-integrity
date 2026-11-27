const path = require('path');
const pak = require('../package.json');

module.exports = {
  dependencies: {
    [pak.name]: {
      root: path.join(__dirname, '..'),
    },
    // Only used by the Android example to sign with the attested hardware key
    '@pagopa/io-react-native-crypto': {
      platforms: {
        ios: null,
      },
    },
  },
};
