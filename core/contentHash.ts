/**
 * `hashContent` — SHA-256 hex of a canonical (JSON-stringified) payload.
 *
 * Pure and isomorphic: `crypto.subtle` is native in both the browser (Vite) and
 * Deno (Edge Functions), no dependency. Hashes the PLAINTEXT (never the
 * ciphertext): AES-GCM uses a random nonce, so identical plaintext produces
 * different ciphertext every time — ciphertexts are never comparable, only the
 * plaintext content is.
 *
 * Fully generic — no app-specific knowledge required (unlike `StorageAdapter`/
 * `KeyProvider`, which genuinely need app-supplied implementations). That's why
 * this lives in DataCloak's core rather than being an app-injected function:
 * `defineStore`'s `contentHash: true` just turns this on, nothing to supply.
 */
export async function hashContent(payload: unknown): Promise<string> {
  const json = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(json);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
