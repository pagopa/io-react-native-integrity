import * as React from 'react';
import AndroidApp from './AndroidApp';
import { Platform } from 'react-native';

export default function App() {
  return Platform.OS === 'android' ? <AndroidApp /> : <></>;
}
