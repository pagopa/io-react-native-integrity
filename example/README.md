This is a new [**React Native**](https://reactnative.dev) project, bootstrapped using [`@react-native-community/cli`](https://github.com/react-native-community/cli).

# Getting Started

> **Note**: Make sure you have completed the [React Native - Environment Setup](https://reactnative.dev/docs/environment-setup) instructions till "Creating a new application" step, before proceeding.

## NodeJS and Ruby

To run the project you need to install the correct version of NodeJS and Ruby.
We recommend the use of a virtual environment of your choice. For ease of use, this guide adopts [nodenv](https://github.com/nodenv/nodenv) for NodeJS, [rbenv](https://github.com/rbenv/rbenv) for Ruby.

The node version used in this project is stored in [.node-version](.node-version),
while the version of Ruby is stored in [.ruby-version](.ruby-version).

## Build the app

```bash
# Install NodeJS with nodenv, the returned version should match the one in the .node-version file
$ nodenv install && nodenv version

# Install Ruby with rbenv, the returned version should match the one in the .ruby-version file
$ rbenv install && rbenv version

# Install yarn and rehash to install shims
$ npm install -g yarn && nodenv rehash

# Install bundle
$ gem install bundle

# Install the required Gems from the Gemfile
# Run this only during the first setup and when Gems dependencies change
$ bundle install

# Install dependencies
# Run this only during the first setup and when JS dependencies change
$ yarn install

# Install podfiles when targeting iOS (ignore this step for Android)
# Run this only during the first setup and when Pods dependencies change
$ cd iOS && bundle exec pod install && cd ..
```

## Run the app

```bash
## Android
$ yarn react-native run-android

## iOS
$ yarn react-native run-ios
```
