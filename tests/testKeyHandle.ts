/**
 * Test-only `KeyHandle` fixture. DataCloak's own test suite must never depend on
 * app code (`src/lib/passkeyPrf.ts` or any other consumer) — that's backwards, the
 * dependency only ever goes the other way. Any salt/info works here: tests never
 * need to match a real app's production values, they just need a deterministic,
 * working `CryptoHandle`.
 */
import {
  createKeyHandle,
  asRawDekBytes,
  type KeyHandle,
} from "../core/keyDerivation.ts";

const TEST_PID_SALT = new Uint8Array(32).fill(42);
const TEST_PID_INFO = "test-pid-info";

// Firma volutamente non-branded: questo helper prende sempre randomBytes() usa-e-getta
// nei test, mai un vero segreto — richiedere asRawDekBytes() a ~130 call site di test
// non aggiungerebbe protezione reale, solo rumore. Il cast avviene qui, una sola volta.
export function createDekHandle(rawBytes: Uint8Array): KeyHandle {
  return createKeyHandle(asRawDekBytes(rawBytes), TEST_PID_SALT, TEST_PID_INFO);
}
