import React from 'react';
import { ActivityIndicator, Button, StyleSheet, View } from 'react-native';

type Props = {
  /**
   * The title of the button
   */
  title: string;
  /**
   * The action to perform when the button is pressed
   */
  onPress: () => void;
  /**
   * Whether the button is in a loading state
   */
  loading?: boolean;
};

/**
 * A button component with a loader that can be shown when the button is in a loading state.
 * The loader is a spinner showed at the right of the button title.
 */
const ButtonWithLoader = (props: Props) => {
  return (
    <View style={styles.container}>
      <Button
        title={props.title}
        onPress={props.onPress}
        disabled={props.loading}
      />
      {props.loading && <ActivityIndicator />}
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flexDirection: 'row', alignItems: 'center' },
});

export default ButtonWithLoader;
