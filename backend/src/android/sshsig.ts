import * as crypto from 'crypto';

/**
 * Minimal implementation of the OpenSSH signature format (SSHSIG) verification, equivalent to:
 * `ssh-keygen -Y verify -f allowed_signers -I <principal> -n <namespace> -s <signature> < <message>`
 * Only Ed25519 keys are supported.
 * {@link https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig}
 * {@link https://man.openbsd.org/ssh-keygen#ALLOWED_SIGNERS}
 */

const MAGIC_PREAMBLE = 'SSHSIG';
const SIG_VERSION = 1;
const ED25519_KEY_TYPE = 'ssh-ed25519';
const SUPPORTED_HASH_ALGORITHMS = ['sha256', 'sha512'];
const ARMOR_BEGIN = '-----BEGIN SSH SIGNATURE-----';
const ARMOR_END = '-----END SSH SIGNATURE-----';

/**
 * An entry of an allowed_signers file.
 */
export type AllowedSigner = {
  principals: string[];
  namespaces?: string[];
  keyType: string;
  publicKeyBlob: Buffer;
};

/**
 * Reader for the SSH wire format.
 */
class SshBufferReader {
  private offset = 0;

  constructor(private readonly buffer: Buffer) {}

  readBytes(length: number): Buffer {
    if (this.offset + length > this.buffer.length) {
      throw new Error('Unexpected end of SSH data');
    }
    const result = this.buffer.subarray(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  readUInt32(): number {
    return this.readBytes(4).readUInt32BE(0);
  }

  readString(): Buffer {
    return this.readBytes(this.readUInt32());
  }

  isAtEnd(): boolean {
    return this.offset === this.buffer.length;
  }
}

/**
 * Encodes a value as an SSH string, which is a uint32 length followed by the data.
 * @param value - The value to encode.
 * @returns the encoded value.
 */
const sshString = (value: Buffer | string) => {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf-8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  return Buffer.concat([length, data]);
};

/**
 * Splits an allowed_signers line in fields, keeping quoted sections together.
 * @param line - The line to split.
 * @returns the fields of the line.
 */
const splitFields = (line: string) => {
  const fields: string[] = [];
  let current = '';
  let quoted = false;
  for (const char of line) {
    if (char === '"') {
      quoted = !quoted;
      current += char;
    } else if (/\s/.test(char) && !quoted) {
      if (current) fields.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  if (quoted) throw new Error('Unterminated quote in allowed_signers line');
  if (current) fields.push(current);
  return fields;
};

/**
 * Parses the options field of an allowed_signers line.
 * Only the `namespaces` option is supported, lines with other options are rejected
 * so that restrictions such as `valid-before` are never silently ignored.
 * @param options - The options field.
 * @returns the list of the allowed namespaces.
 */
const parseOptions = (options: string) => {
  const match = /^namespaces="([^"]*)"$/i.exec(options);
  if (!match || match[1] === undefined) {
    throw new Error(`Unsupported allowed_signers options: ${options}`);
  }
  return match[1].split(',').map((namespace) => namespace.trim());
};

/**
 * Parses the content of an allowed_signers file.
 * Each line has the format `principals [options] keytype base64-key [comment]`.
 * @param content - The content of the allowed_signers file.
 * @returns the list of the allowed signers.
 * @throws {Error} - If a line is malformed or uses unsupported options.
 */
export const parseAllowedSigners = (content: string): AllowedSigner[] =>
  content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map((line) => {
      const fields = splitFields(line);
      const [principals, second, ...rest] = fields;
      if (!principals || !second) {
        throw new Error('Malformed allowed_signers line');
      }
      const hasOptions = !/^(ssh-|ecdsa-|sk-)/.test(second);
      const namespaces = hasOptions ? parseOptions(second) : undefined;
      const [keyType, encodedKey] = hasOptions ? rest : [second, ...rest];
      if (!keyType || !encodedKey) {
        throw new Error('Malformed allowed_signers line');
      }
      const publicKeyBlob = Buffer.from(encodedKey, 'base64');
      const blobKeyType = new SshBufferReader(publicKeyBlob)
        .readString()
        .toString('utf-8');
      if (blobKeyType !== keyType) {
        throw new Error('Key type mismatch in allowed_signers line');
      }
      return {
        principals: principals.split(','),
        namespaces,
        keyType,
        publicKeyBlob,
      };
    });

/**
 * Converts an SSH Ed25519 public key blob into a {@link crypto.KeyObject}.
 * @param publicKeyBlob - The SSH public key blob.
 * @returns the public key.
 */
const ed25519PublicKey = (publicKeyBlob: Buffer) => {
  const reader = new SshBufferReader(publicKeyBlob);
  const keyType = reader.readString().toString('utf-8');
  const rawKey = reader.readString();
  if (
    keyType !== ED25519_KEY_TYPE ||
    rawKey.length !== 32 ||
    !reader.isAtEnd()
  ) {
    throw new Error(`Unsupported SSH public key type: ${keyType}`);
  }
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: rawKey.toString('base64url') },
    format: 'jwk',
  });
};

/**
 * Decodes an armored SSH signature.
 * @param armoredSignature - The armored signature.
 * @returns the decoded signature fields.
 */
const decodeSignature = (armoredSignature: string) => {
  const trimmed = armoredSignature.trim();
  if (!trimmed.startsWith(ARMOR_BEGIN) || !trimmed.endsWith(ARMOR_END)) {
    throw new Error('Invalid SSH signature armor');
  }
  const blob = Buffer.from(
    trimmed.slice(ARMOR_BEGIN.length, -ARMOR_END.length).replace(/\s/g, ''),
    'base64'
  );
  const reader = new SshBufferReader(blob);
  if (reader.readBytes(6).toString('utf-8') !== MAGIC_PREAMBLE) {
    throw new Error('Invalid SSH signature preamble');
  }
  if (reader.readUInt32() !== SIG_VERSION) {
    throw new Error('Unsupported SSH signature version');
  }
  const publicKeyBlob = reader.readString();
  const namespace = reader.readString().toString('utf-8');
  const reserved = reader.readString();
  const hashAlgorithm = reader.readString().toString('utf-8');
  const signatureBlob = reader.readString();
  if (!reader.isAtEnd()) {
    throw new Error('Trailing data in SSH signature');
  }
  return { publicKeyBlob, namespace, reserved, hashAlgorithm, signatureBlob };
};

/**
 * Verifies an SSHSIG signature of a message against an allowed_signers file.
 * @param params.message - The signed message.
 * @param params.armoredSignature - The armored SSH signature.
 * @param params.allowedSigners - The content of the allowed_signers file.
 * @param params.principal - The expected principal, e.g. an email address.
 * @param params.namespace - The expected signature namespace.
 * @throws {Error} - If the signature is invalid or it hasn't been made by an allowed signer.
 */
export const verifySshSignature = ({
  message,
  armoredSignature,
  allowedSigners,
  principal,
  namespace,
}: {
  message: Buffer;
  armoredSignature: string;
  allowedSigners: string;
  principal: string;
  namespace: string;
}) => {
  const signature = decodeSignature(armoredSignature);
  if (signature.namespace !== namespace) {
    throw new Error(
      `Unexpected SSH signature namespace: ${signature.namespace}`
    );
  }
  if (!SUPPORTED_HASH_ALGORITHMS.includes(signature.hashAlgorithm)) {
    throw new Error(
      `Unsupported SSH signature hash algorithm: ${signature.hashAlgorithm}`
    );
  }
  const signer = parseAllowedSigners(allowedSigners).find(
    (entry) =>
      entry.principals.includes(principal) &&
      (entry.namespaces === undefined ||
        entry.namespaces.includes(namespace)) &&
      entry.publicKeyBlob.equals(signature.publicKeyBlob)
  );
  if (!signer) {
    throw new Error('SSH signature has not been made by an allowed signer');
  }

  const signatureReader = new SshBufferReader(signature.signatureBlob);
  const signatureType = signatureReader.readString().toString('utf-8');
  const rawSignature = signatureReader.readString();
  if (signatureType !== signer.keyType || !signatureReader.isAtEnd()) {
    throw new Error(`Unexpected SSH signature type: ${signatureType}`);
  }

  const signedData = Buffer.concat([
    Buffer.from(MAGIC_PREAMBLE, 'utf-8'),
    sshString(signature.namespace),
    sshString(signature.reserved),
    sshString(signature.hashAlgorithm),
    sshString(
      crypto.createHash(signature.hashAlgorithm).update(message).digest()
    ),
  ]);
  const isValid = crypto.verify(
    null,
    signedData,
    ed25519PublicKey(signer.publicKeyBlob),
    rawSignature
  );
  if (!isValid) {
    throw new Error('Invalid SSH signature');
  }
};
