import { CBOR } from '@pagopa/io-react-native-iso18013';
import { z } from 'zod';

// io-react-native-iso18013 returns CBOR byte strings as base64url
const Base64UrlToBase64 = z.string().transform((value) =>
  value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=')
);

const DecodedAssertion = z.object({
  signature: Base64UrlToBase64,
  authenticatorData: Base64UrlToBase64,
});

export type DecodedAssertion = z.output<typeof DecodedAssertion>;

/**
 * Decodes a base64 CBOR iOS assertion into base64 encoded `signature` and
 * `authenticatorData`.
 */
export async function decodeAssertion(
  assertion: string
): Promise<DecodedAssertion> {
  return DecodedAssertion.parseAsync(await CBOR.decode(assertion));
}
