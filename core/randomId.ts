/**
 * RFC4122 v4 UUID generator built on `@noble/ciphers`'s `randomBytes` — the same
 * dependency the crypto core already requires, cross-platform by construction
 * (Node/browser/React Native all delegate `randomBytes` to the right CSPRNG per
 * platform, no extra polyfill needed beyond what noble itself already requires).
 *
 * Deliberately NOT `crypto.randomUUID()`: that global is inconsistent across
 * environments (missing or needs polyfilling on some React Native/Hermes versions)
 * — this is the one thing in `core/` that used to assume a browser-shaped `crypto`
 * global, found during RN-readiness modeling. Only consumer today:
 * `defineStore`'s `identity: "many"` id generation.
 */
import { randomBytes } from "@noble/ciphers/utils.js";

export function randomId(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
