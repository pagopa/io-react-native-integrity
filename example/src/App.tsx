import * as React from 'react';
import { Platform } from 'react-native';
import IosApp from './IosApp';
import AndroidApp from './AndroidApp';

export default function App() {
  return Platform.OS === 'ios' ? <IosApp /> : <AndroidApp />;
}
