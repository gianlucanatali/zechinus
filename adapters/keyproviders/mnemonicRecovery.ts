/**
 * BIP39-mnemonic-based key recovery. Any zero-knowledge E2E app needs some way to
 * recover a lost key (nobody else CAN reset it — that's the point of zero-knowledge),
 * and a mnemonic recovery phrase is the standard pattern (crypto wallets, password
 * managers) — this isn't app-specific logic, so it lives here. What's app-specific is
 * config: entropy strength (word count), which wordlist(s) to generate/accept, and the
 * HKDF salt/info for deriving a KEK from the phrase (IMMUTABLE once any user has a
 * recovery phrase — changing it makes existing phrases derive a different KEK).
 *
 * Factory-bound, same shape as `webauthnKeyProvider(config)`: the app supplies its
 * config once, the returned object's methods take no config after that.
 */
import {
  generateMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { deriveKey } from "../../core/keyDerivation.ts";

export interface MnemonicRecoveryConfig {
  /** Entropy bits — 256 = 24 words (matches AES-256 key strength), 128 = 12 words. */
  entropyBits: 128 | 160 | 192 | 224 | 256;
  /** Wordlist used to generate new phrases. */
  wordlist: string[];
  /** Wordlists accepted when validating/deriving — include older wordlists for backward-compat. */
  acceptWordlists: string[][];
  /** HKDF salt/info for deriving a KEK from the phrase. IMMUTABLE once any recovery phrase exists. */
  kekSalt: Uint8Array;
  kekInfo: string;
}

export interface MnemonicRecovery {
  /** Generates a new recovery phrase. Show it to the user once — never persist it anywhere. */
  generateWords(): string;
  /** True if `words` is a valid BIP39 phrase against any of the configured wordlists. */
  validateWords(words: string): boolean;
  /** Deterministic: same words always derive the same KEK. Throws for invalid words. */
  deriveKEK(words: string): Uint8Array;
}

function detectWordlist(words: string, wordlists: string[][]): string[] | null {
  const normalized = words.trim().toLowerCase();
  for (const wl of wordlists) {
    if (validateMnemonic(normalized, wl)) return wl;
  }
  return null;
}

export function mnemonicRecovery(
  config: MnemonicRecoveryConfig,
): MnemonicRecovery {
  return {
    generateWords() {
      return generateMnemonic(config.wordlist, config.entropyBits);
    },
    validateWords(words) {
      return detectWordlist(words, config.acceptWordlists) !== null;
    },
    deriveKEK(words) {
      const wordlist = detectWordlist(words, config.acceptWordlists);
      if (!wordlist) {
        throw new Error("mnemonicRecovery.deriveKEK: invalid BIP39 words");
      }
      const entropy = mnemonicToEntropy(words.trim().toLowerCase(), wordlist);
      return deriveKey(entropy, config.kekSalt, config.kekInfo, 32);
    },
  };
}
