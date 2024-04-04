import * as React from 'react';
import { Platform } from 'react-native';
import IosApp from './IosApp';

export default function App() {
  return Platform.OS === 'ios' ? <IosApp /> : <></>;
}
