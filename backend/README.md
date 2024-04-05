# Getting Started

### This is a dev server to test integrity check integration with the example app adding verification steps.

## NodeJS

To run the project you need to install the correct version of NodeJS.
We recommend the use of a virtual environment of your choice. For ease of use, this guide adopts [nodenv](https://github.com/nodenv/nodenv) for NodeJS.
The node version used in this project is stored in [.node-version](.node-version).

## Build the app

```bash
# Install NodeJS with nodenv, the returned version should match the one in the .node-version file
$ nodenv install && nodenv version

# Install yarn and rehash to install shims
$ npm install -g yarn && nodenv rehash

# Install dependencies
# Run this only during the first setup and when JS dependencies change
$ yarn install
```

## Android environment

In order to use the Android verification endpoints you need to enable the Google Play Integrity API service on the Google Cloud project related to the `GOOGLE_CLOUD_PROJECT_NUMBER` provided in the example app `.env` file. Referer to the [setup page](https://developer.android.com/google/play/integrity/setup) for more information.

Be sure to fill the `.env` file with the required enviroment variables:

```javascript
ANDROID_BUNDLE_IDENTIFIER =
GOOGLE_APPLICATION_CREDENTIALS =
```

`ANDROID_BUNDLE_IDENTIFIER` is the package name of the app you want to verify, it's already included in the `.env.local` file for the example app of this project.

`GOOGLE_APPLICATION_CREDENTIALS` consists of a JSON string with the service account credentials. Refer to the [instructions](https://developer.android.com/google/play/integrity/standard#decrypt-and) for more information.

## Run the app

```bash
# First edit .env to add the required environment variables according to the platform you want to test
$ cp .env.local .env
$ yarn start
```
