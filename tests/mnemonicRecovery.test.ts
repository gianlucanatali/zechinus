/**
 * BIP39-mnemonic-based recovery — any zero-knowledge E2E app needs SOME way to
 * recover a lost key (that's the cost of zero-knowledge: no one else can reset it
 * for you), and a mnemonic recovery phrase is the standard, well-understood pattern
 * (crypto wallets, password managers). Generic: wordlist/entropy/salt are config, not
 * hardcoded — an app picks its own word count and wordlist(s). Factory-bound, same
 * shape as `webauthnKeyProvider(config)` — the app constructs it once with its own
 * config, consumers call the bound methods with no config repeated at every call site.
 *
 * Golden vector: a fixed 24-word Italian phrase, KEK derived once and hardcoded
 * here as the regression oracle.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { mnemonicRecovery } from "../adapters/mnemonicRecovery.ts";
import { wordlist as italian } from "@scure/bip39/wordlists/italian.js";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";

const PRF_SALT = new Uint8Array([
  116, 195, 89, 245, 113, 126, 174, 242, 74, 10, 188, 78, 55, 11, 126, 179, 38,
  253, 76, 48, 109, 72, 117, 62, 149, 107, 210, 250, 151, 131, 161, 158,
]);

const FIXED_WORDS =
  "caloria toscano paese tara perplesso calcolo batosta mazurca meccanico burrasca romantico intonaco porre editoria umorismo esofago longevo davanti sorteggio limatura congelare zibetto uccisore ritardo";

function testRecovery() {
  return mnemonicRecovery({
    entropyBits: 256,
    wordlist: italian,
    acceptWordlists: [italian, english],
    kekSalt: PRF_SALT,
    kekInfo: "myapp-kek-recovery-v1",
  });
}

test("generateWords: 256 bits of entropy → 24 words, valid against the same wordlist", () => {
  const recovery = testRecovery();
  const words = recovery.generateWords();
  assert.equal(words.trim().split(/\s+/).length, 24);
  assert.equal(recovery.validateWords(words), true);
});

test("validateWords: false for words not in any accepted wordlist", () => {
  const recovery = testRecovery();
  assert.equal(
    recovery.validateWords("not real bip39 words at all here"),
    false,
  );
});

test("validateWords: accepts multiple configured wordlists (backward-compat with an older default)", () => {
  const recovery = testRecovery();
  const englishTestVector =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  assert.equal(recovery.validateWords(englishTestVector), true);
});

test("deriveKEK: matches the golden vector", () => {
  const recovery = testRecovery();
  const kek = recovery.deriveKEK(FIXED_WORDS);
  assert.equal(
    Buffer.from(kek).toString("hex"),
    "3d8e00bf4b1d9fe8cc8a4564c83cf183cf2948510c91e8fa22347efa5cabf69b".slice(
      0,
      64,
    ),
  );
});

test("deriveKEK: deterministic — same words always derive the same KEK", () => {
  const recovery = testRecovery();
  assert.deepEqual(
    recovery.deriveKEK(FIXED_WORDS),
    recovery.deriveKEK(FIXED_WORDS),
  );
});

test("deriveKEK: throws an explicit error for invalid words, never silently derives from garbage", () => {
  const recovery = testRecovery();
  assert.throws(
    () => recovery.deriveKEK("not valid bip39 words"),
    /invalid BIP39 words/,
  );
});

test("mnemonicRecovery: two differently-configured instances derive different KEKs from the same words (config actually flows through)", () => {
  const a = mnemonicRecovery({
    entropyBits: 256,
    wordlist: italian,
    acceptWordlists: [italian],
    kekSalt: new Uint8Array(32).fill(1),
    kekInfo: "info-a",
  });
  const b = mnemonicRecovery({
    entropyBits: 256,
    wordlist: italian,
    acceptWordlists: [italian],
    kekSalt: new Uint8Array(32).fill(2),
    kekInfo: "info-b",
  });
  assert.notDeepEqual(a.deriveKEK(FIXED_WORDS), b.deriveKEK(FIXED_WORDS));
});
