# Getting Started

### This is a dev server to test integrity check integration with the example app adding verification steps.

## NodeJS

To run the project you need to install the correct version of NodeJS.
We recommend the use of a virtual environment of your choice. For ease of use, this guide adopts [nodenv](https://github.com/nodenv/nodenv) for NodeJS, [rbenv](https://github.com/rbenv/rbenv) for Ruby.

The node version used in this project is stored in [.node-version](.node-version),
while the version of Ruby is stored in [.ruby-version](.ruby-version).

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

## Run the app

```bash
# First edit .env to add a BACKEND_ADDRESS (is required to use real local ip address instead localhost)
$ cp .env.local env.local
$ yarn start
```
