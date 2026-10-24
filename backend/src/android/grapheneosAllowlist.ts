import * as fs from 'fs';
import { verifySshSignature } from './sshsig';

/**
 * Official list of the GrapheneOS verified boot key fingerprints, signed by GrapheneOS.
 * {@link https://grapheneos.org/articles/attestation-compatibility-guide}
 */
export const GRAPHENEOS_ATTESTATION_URL =
  'https://grapheneos.org/attestation.json';
export const GRAPHENEOS_ATTESTATION_SIGNATURE_URL =
  'https://grapheneos.org/attestation.json.sig';
const GRAPHENEOS_SIGNER_PRINCIPAL = 'contact@grapheneos.org';
const GRAPHENEOS_SIGNATURE_NAMESPACE = 'attestation keys';

/**
 * Snapshot of the GrapheneOS verified boot key fingerprints published in the attestation compatibility
 * guide on 2026-10-23. It is only used as initial "last known good" list until the signed list is
 * downloaded and verified, its timestamp is 0 so that any signed list replaces it.
 */
export const GRAPHENEOS_ALLOWLIST_SNAPSHOT = {
  verifiedBootKeys: [
    'd8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80', // Pixel 10a
    '55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3', // Pixel 10 Pro Fold
    '141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74', // Pixel 10 Pro XL
    '4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093', // Pixel 10 Pro
    '3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7', // Pixel 10
    '0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b', // Pixel 9a
    'af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c', // Pixel 9 Pro Fold
    '55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023', // Pixel 9 Pro XL
    'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86', // Pixel 9 Pro
    '9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de', // Pixel 9
    '096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e', // Pixel 8a
    '896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c', // Pixel 8 Pro
    'cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233', // Pixel 8
    'ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842', // Pixel Fold
    '94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230', // Pixel Tablet
    '508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4', // Pixel 7a
    'bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f', // Pixel 7 Pro
    '3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1', // Pixel 7
    '08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031', // Pixel 6a
    '439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c', // Pixel 6 Pro
    'f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8', // Pixel 6
  ],
  timestamp: 0,
};

export type GrapheneOsAllowlistOptions = {
  /**
   * Content of the GrapheneOS allowed_signers file (https://grapheneos.org/allowed_signers),
   * which must be pinned in the configuration after being verified out of band.
   * When missing the signed list can't be verified and only the snapshot is used.
   */
  allowedSigners?: string;
  /** Optional file used to persist the last verified list and signature across restarts. */
  cacheFile?: string;
  attestationUrl?: string;
  signatureUrl?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
};

type AttestationKeysFile = {
  verifiedBootKeys: string[];
  timestamp: number;
};

/**
 * Parses and validates the GrapheneOS attestation.json file.
 * @param json - The content of the file.
 * @returns the parsed file.
 * @throws {Error} - If the file doesn't match the expected schema.
 */
const parseAttestationKeysFile = (json: string): AttestationKeysFile => {
  const parsed: unknown = JSON.parse(json);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid GrapheneOS attestation keys file');
  }
  const { verifiedBootKeys, timestamp } = parsed as Record<string, unknown>;
  if (
    !Array.isArray(verifiedBootKeys) ||
    !verifiedBootKeys.every(
      (key) => typeof key === 'string' && /^[0-9a-fA-F]{64}$/.test(key)
    ) ||
    typeof timestamp !== 'number' ||
    !Number.isInteger(timestamp)
  ) {
    throw new Error('Invalid GrapheneOS attestation keys file');
  }
  return {
    verifiedBootKeys: (verifiedBootKeys as string[]).map((key) =>
      key.toLowerCase()
    ),
    timestamp,
  };
};

/**
 * Provider of the allowed GrapheneOS verified boot keys.
 * The list is downloaded from {@link GRAPHENEOS_ATTESTATION_URL} and accepted only if:
 * - its OpenSSH signature has been made by the pinned GrapheneOS key with the "attestation keys" namespace;
 * - its timestamp is not older than the last accepted one, to protect against downgrade attacks.
 * On any failure the last accepted list is kept, it never fails open.
 */
export class GrapheneOsAllowlist {
  private keys: ReadonlySet<string> = new Set(
    GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys
  );
  private timestamp = GRAPHENEOS_ALLOWLIST_SNAPSHOT.timestamp;

  constructor(private readonly options: GrapheneOsAllowlistOptions = {}) {
    this.loadCache();
  }

  /**
   * @returns the allowed verified boot keys, lowercase hex encoded.
   */
  getKeys(): ReadonlySet<string> {
    return this.keys;
  }

  /**
   * @returns the timestamp of the accepted list, 0 for the bundled snapshot.
   */
  getTimestamp(): number {
    return this.timestamp;
  }

  /**
   * Verifies and applies a signed list.
   * @param json - The content of attestation.json.
   * @param signature - The content of attestation.json.sig.
   * @throws {Error} - If the signature is invalid, the file is malformed or older than the accepted one.
   */
  apply(json: string, signature: string) {
    const { allowedSigners } = this.options;
    if (!allowedSigners) {
      throw new Error('The GrapheneOS allowed signers are not configured');
    }
    verifySshSignature({
      message: Buffer.from(json, 'utf-8'),
      armoredSignature: signature,
      allowedSigners,
      principal: GRAPHENEOS_SIGNER_PRINCIPAL,
      namespace: GRAPHENEOS_SIGNATURE_NAMESPACE,
    });
    const file = parseAttestationKeysFile(json);
    if (file.timestamp < this.timestamp) {
      throw new Error(
        `GrapheneOS attestation keys downgrade detected: ${file.timestamp} < ${this.timestamp}`
      );
    }
    this.keys = new Set(file.verifiedBootKeys);
    this.timestamp = file.timestamp;
  }

  /**
   * Downloads, verifies and applies the signed list.
   * @throws {Error} - If the download or the verification fails, the current list is kept.
   */
  async refresh() {
    const fetchFn = this.options.fetchFn ?? fetch;
    const download = async (url: string) => {
      const res = await fetchFn(url, {
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 10000),
      });
      if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
      return res.text();
    };
    const [json, signature] = await Promise.all([
      download(this.options.attestationUrl ?? GRAPHENEOS_ATTESTATION_URL),
      download(
        this.options.signatureUrl ?? GRAPHENEOS_ATTESTATION_SIGNATURE_URL
      ),
    ]);
    this.apply(json, signature);
    this.saveCache(json, signature);
  }

  /**
   * Refreshes the list now and then periodically, logging failures.
   * @param intervalMs - The refresh interval, 24 hours by default.
   * @returns the interval timer.
   */
  startAutoRefresh(intervalMs = 24 * 60 * 60 * 1000) {
    const refresh = () =>
      this.refresh().catch((e) =>
        console.warn(
          `[GrapheneOS allowlist] refresh failed, keeping the list with timestamp ${this.timestamp}: ${e}`
        )
      );
    refresh();
    return setInterval(refresh, intervalMs).unref();
  }

  private loadCache() {
    const { cacheFile, allowedSigners } = this.options;
    if (!cacheFile || !allowedSigners || !fs.existsSync(cacheFile)) return;
    try {
      const { json, signature } = JSON.parse(
        fs.readFileSync(cacheFile, 'utf-8')
      );
      this.apply(json, signature);
    } catch (e) {
      console.warn(`[GrapheneOS allowlist] ignoring invalid cache: ${e}`);
    }
  }

  private saveCache(json: string, signature: string) {
    const { cacheFile } = this.options;
    if (!cacheFile) return;
    fs.writeFileSync(cacheFile, JSON.stringify({ json, signature }));
  }
}
