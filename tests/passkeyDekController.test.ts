/**
 * `passkeyDekController` — generic orchestration for a WebAuthn-passkey +
 * BIP39-recovery zero-knowledge unlock flow: register, unlock, unlock-via-recovery,
 * add an additional passkey to an already-unlocked DEK, lock. Every step here is the
 * same for ANY app doing this pattern — only the storage of the wrapped keys
 * (`PasskeyWrapStorage`) and how raw bytes become a real `KeyHandle` (`createHandle`,
 * e.g. Worker-isolated or plain) are app-specific, both injected via config.
 *
 * `navigator.credentials` doesn't exist under `node --test` (same boundary as
 * `webauthnKeyProvider.test.ts`) — tests use a fake `WebauthnKeyProvider` double,
 * never the real browser-backed factory.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  createPasskeyDekController,
  type PasskeyWrapStorage,
  type WrappedKeyRow,
} from "../adapters/passkeyDekController.ts";
import { createKeyHandle, asRawDekBytes } from "../core/keyDerivation.ts";
import type { WebauthnKeyProvider } from "../adapters/webauthnKeyProvider.ts";
import type { MnemonicRecovery } from "../adapters/mnemonicRecovery.ts";
import { deriveKey } from "../core/keyDerivation.ts";

function bytesFromRange(len: number, fn: (i: number) => number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = fn(i);
  return out;
}

const TEST_PID_SALT = new Uint8Array(32).fill(3);
const TEST_KEK_SALT = new Uint8Array(32).fill(5);

/** Deterministic fake: PRF output = a fixed pattern per credential id. */
function fakeWebauthnProvider(): WebauthnKeyProvider {
  let nextId = 1;
  const prfByCredential = new Map<string, Uint8Array>();

  function prfFor(credentialId: string): Uint8Array {
    let prf = prfByCredential.get(credentialId);
    if (!prf) {
      const seed = Number(credentialId.split("-")[1]);
      prf = bytesFromRange(32, (i) => (i + seed * 10) % 256);
      prfByCredential.set(credentialId, prf);
    }
    return prf;
  }

  return {
    async registerPasskeyWithPRF() {
      const credentialId = `cred-${nextId++}`;
      const prf = prfFor(credentialId);
      return { credentialId, prfOutput: prf.buffer as ArrayBuffer };
    },
    async getDEKFromPasskey() {
      throw new Error(
        "fakeWebauthnProvider: getDEKFromPasskey unused in these tests",
      );
    },
    async getPRFOutput(credentialId = "cred-1") {
      return prfFor(credentialId).buffer as ArrayBuffer;
    },
    async getPRFOutputWithCredentialId(credentialId = "cred-1") {
      return {
        prfOutput: prfFor(credentialId).buffer as ArrayBuffer,
        credentialId,
      };
    },
    deriveKEKFromPRF(prfOutput: ArrayBuffer) {
      return deriveKey(
        new Uint8Array(prfOutput),
        TEST_KEK_SALT,
        "kek-info",
        32,
      );
    },
  };
}

/** Fake BIP39 recovery: "words" is just a plain string used as the entropy source. */
function fakeMnemonicRecovery(): MnemonicRecovery {
  let generatedCount = 0;
  return {
    generateWords() {
      generatedCount++;
      return generatedCount === 1
        ? "fixed test recovery words"
        : `fixed test recovery words ${generatedCount}`;
    },
    validateWords(words) {
      return (
        words === "fixed test recovery words" ||
        /^fixed test recovery words \d+$/.test(words) ||
        words === ""
      );
    },
    deriveKEK(words) {
      if (!this.validateWords(words) || words === "") {
        throw new Error("fakeMnemonicRecovery: invalid words");
      }
      return deriveKey(
        new TextEncoder().encode(words),
        TEST_KEK_SALT,
        "recovery-kek-info",
        32,
      );
    },
  };
}

/** In-memory `PasskeyWrapStorage` double — mirrors the shape of a real DB-backed one. */
function memoryWrapStorage(): PasskeyWrapStorage {
  const passkeyWraps = new Map<string, WrappedKeyRow>(); // key: `${userId}|${credentialId}`
  let recoveryWrap: { userId: string; wrap: WrappedKeyRow } | null = null;

  return {
    async countPasskeyWraps(userId) {
      return [...passkeyWraps.keys()].filter((k) => k.startsWith(`${userId}|`))
        .length;
    },
    async loadPasskeyWrap(userId, credentialId) {
      return passkeyWraps.get(`${userId}|${credentialId}`) ?? null;
    },
    async savePasskeyWrap(userId, credentialId, wrapped) {
      passkeyWraps.set(`${userId}|${credentialId}`, wrapped);
    },
    async loadRecoveryWrap(userId) {
      return recoveryWrap && recoveryWrap.userId === userId
        ? recoveryWrap.wrap
        : null;
    },
    async saveRecoveryWrap(userId, wrapped) {
      recoveryWrap = { userId, wrap: wrapped };
    },
  };
}

function testCreateHandle(rawBytes: ReturnType<typeof asRawDekBytes>) {
  return createKeyHandle(rawBytes, TEST_PID_SALT, "test-pid-info");
}

test("registerPasskey → confirm: persists both wraps, activates the DEK, marks setup done", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  assert.equal(controller.getCryptoHandle(), null);
  const { recoveryWords, confirm } = await controller.registerPasskey(
    "user-1",
    "user-1@test.example",
  );
  assert.equal(recoveryWords, "fixed test recovery words");
  assert.equal(controller.getCryptoHandle(), null, "confirm() not called yet");

  await confirm();

  assert.notEqual(controller.getCryptoHandle(), null);
  assert.equal(controller.getSetupStatus(), "done");
  assert.equal(await storage.countPasskeyWraps("user-1"), 1);
  assert.notEqual(await storage.loadRecoveryWrap("user-1"), null);
});

test("unlockWithPasskey: recovers the exact DEK set during registration", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  const pidAfterSetup = controller.getCryptoHandle()!.pid;

  controller.lock();
  assert.equal(controller.getCryptoHandle(), null);

  await controller.unlockWithPasskey("user-1");
  assert.equal(controller.getCryptoHandle()!.pid, pidAfterSetup);
});

test("getUnlockCredentialId: null until unlocked, set by registerPasskey/confirm, cleared by lock", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  assert.equal(controller.getUnlockCredentialId(), null);
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  assert.equal(controller.getUnlockCredentialId(), "cred-1");

  controller.lock();
  assert.equal(controller.getUnlockCredentialId(), null);
});

test("getUnlockCredentialId: reflects the credential used by unlockWithPasskey", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  controller.lock();

  await controller.unlockWithPasskey("user-1", "cred-1");
  assert.equal(controller.getUnlockCredentialId(), "cred-1");
});

test("getUnlockCredentialId: null after unlockWithRecovery — no passkey credential involved", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  assert.equal(controller.getUnlockCredentialId(), "cred-1");
  controller.lock();

  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getUnlockCredentialId(), null);
});

test("getDevicePublicKey: null until unlocked, set by registerPasskey/confirm, cleared by lock", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  assert.equal(controller.getDevicePublicKey(), null);
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  assert.ok(controller.getDevicePublicKey());

  controller.lock();
  assert.equal(controller.getDevicePublicKey(), null);
});

test("getDevicePublicKey: deterministic — re-unlocking with the same credential derives the SAME device public key (nothing persisted, always re-derived)", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  const firstDevicePublicKey = controller.getDevicePublicKey();
  controller.lock();

  await controller.unlockWithPasskey("user-1", "cred-1");
  assert.equal(controller.getDevicePublicKey(), firstDevicePublicKey);
});

test("getDevicePublicKey: null after unlockWithRecovery — no passkey KEK involved", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  assert.ok(controller.getDevicePublicKey());
  controller.lock();

  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getDevicePublicKey(), null);
});

test("getDevicePublicKey: set by addPasskeyToExistingDek too", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await (
    await controller.registerPasskey("user-1", "u@test.example")
  ).confirm();
  controller.lock();
  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getDevicePublicKey(), null);

  await controller.addPasskeyToExistingDek("user-1", "u@test.example");
  assert.ok(controller.getDevicePublicKey());
});

test("unlockWithPasskey: unknown credential throws and never touches the DEK", async () => {
  const storage = memoryWrapStorage();
  const provider = fakeWebauthnProvider();
  const controller = createPasskeyDekController({
    provider,
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  await assert.rejects(() => controller.unlockWithPasskey("user-1"));
  assert.equal(controller.getCryptoHandle(), null);
});

test("unlockWithRecovery: recovers the exact DEK set during registration", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  const pidAfterSetup = controller.getCryptoHandle()!.pid;
  controller.lock();

  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getCryptoHandle()!.pid, pidAfterSetup);
});

test("unlockWithRecovery: invalid words throw and never touch the DEK", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  controller.lock();

  await assert.rejects(() =>
    controller.unlockWithRecovery("user-1", "totally wrong words"),
  );
  assert.equal(controller.getCryptoHandle(), null);
});

test("addPasskeyToExistingDek: a second credential unlocks the SAME dek (rewrap, not rotation)", async () => {
  const storage = memoryWrapStorage();
  const provider = fakeWebauthnProvider();
  const controller = createPasskeyDekController({
    provider,
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  const originalPid = controller.getCryptoHandle()!.pid;

  await controller.addPasskeyToExistingDek("user-1", "u@test.example");
  assert.equal(await storage.countPasskeyWraps("user-1"), 2);

  controller.lock();
  await controller.unlockWithPasskey("user-1", "cred-2");
  assert.equal(
    controller.getCryptoHandle()!.pid,
    originalPid,
    "the second passkey must unlock the SAME dek, not a different one",
  );
});

test("addPasskeyToExistingDek: throws if no dek is currently unlocked", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await assert.rejects(() =>
    controller.addPasskeyToExistingDek("user-1", "u@test.example"),
  );
});

test("checkSetupNeeded: 'needed' with zero wraps, 'done' once at least one exists", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  await controller.checkSetupNeeded("user-1");
  assert.equal(controller.getSetupStatus(), "needed");

  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  await controller.checkSetupNeeded("user-1");
  assert.equal(controller.getSetupStatus(), "done");
});

test("markSetupDone: sets status to done without requiring a wrap to exist (user skipped)", () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  controller.markSetupDone();
  assert.equal(controller.getSetupStatus(), "done");
});

test("setDek: activates a caller-supplied raw DEK directly (dev/test injection path)", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  assert.notEqual(controller.getCryptoHandle(), null);
  assert.equal(controller.getUserId(), "user-1");
});

test("lock: destroys the handle and clears state", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  assert.notEqual(controller.getCryptoHandle(), null);

  controller.lock();
  assert.equal(controller.getCryptoHandle(), null);
});

test("subscribe: fires on unlock and on lock, not spuriously", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  let fired = 0;
  const unsubscribe = controller.subscribe(() => fired++);

  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  assert.equal(
    fired,
    0,
    "registerPasskey alone (before confirm) must not notify",
  );
  await confirm();
  assert.equal(fired, 1, "confirm() activates the dek → one notification");

  controller.lock();
  assert.equal(fired, 2);

  unsubscribe();
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  assert.equal(fired, 2, "unsubscribed callback must not fire again");
});

test("regenerateRecoveryWords: replaces the recovery wrap — old words stop unlocking, new words do", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  const originalPid = controller.getCryptoHandle()!.pid;

  const { recoveryWords: newWords, confirm: confirmRegen } =
    await controller.regenerateRecoveryWords("user-1");
  assert.notEqual(newWords, "fixed test recovery words");
  await confirmRegen();

  controller.lock();

  await assert.rejects(
    () => controller.unlockWithRecovery("user-1", "fixed test recovery words"),
    "old recovery words must stop working after regeneration",
  );

  await controller.unlockWithRecovery("user-1", newWords);
  assert.equal(
    controller.getCryptoHandle()!.pid,
    originalPid,
    "new recovery words must unlock the SAME dek",
  );
});

test("regenerateRecoveryWords: throws if no dek is currently unlocked", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await assert.rejects(() => controller.regenerateRecoveryWords("user-1"));
});

test("getUnlockMethod: null before unlock, 'passkey' after registerPasskey/unlockWithPasskey, 'recovery' after unlockWithRecovery, null after lock", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  assert.equal(controller.getUnlockMethod(), null);

  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  assert.equal(controller.getUnlockMethod(), "passkey");

  controller.lock();
  assert.equal(controller.getUnlockMethod(), null);

  await controller.unlockWithPasskey("user-1");
  assert.equal(controller.getUnlockMethod(), "passkey");

  controller.lock();
  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getUnlockMethod(), "recovery");
});

test("getUnlockMethod: 'passkey' again after addPasskeyToExistingDek following a recovery unlock", async () => {
  const storage = memoryWrapStorage();
  const provider = fakeWebauthnProvider();
  const controller = createPasskeyDekController({
    provider,
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  const { confirm } = await controller.registerPasskey(
    "user-1",
    "u@test.example",
  );
  await confirm();
  controller.lock();

  await controller.unlockWithRecovery("user-1", "fixed test recovery words");
  assert.equal(controller.getUnlockMethod(), "recovery");

  await controller.addPasskeyToExistingDek("user-1", "u@test.example");
  assert.equal(controller.getUnlockMethod(), "passkey");
});

test("getUnlockMethod: 'passkey' after setDek (dev/test injection path)", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  assert.equal(controller.getUnlockMethod(), "passkey");
});

// --- DEK rotation: beginRotation / getPreviousCryptoHandle / completeRotationSession

test("beginRotation: promotes the new DEK to current, keeps the old one as getPreviousCryptoHandle()", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  const oldHandle = controller.getCryptoHandle();
  assert.equal(controller.getPreviousCryptoHandle(), null);

  await controller.beginRotation(
    asRawDekBytes(bytesFromRange(32, (i) => i + 100)),
  );

  assert.notEqual(controller.getCryptoHandle(), null);
  assert.notEqual(controller.getCryptoHandle(), oldHandle);
  assert.equal(controller.getPreviousCryptoHandle(), oldHandle);
});

test("beginRotation: throws if no DEK is currently unlocked", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await assert.rejects(() =>
    controller.beginRotation(asRawDekBytes(bytesFromRange(32, (i) => i))),
  );
});

test("beginRotation: notifies subscribers", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  let fired = 0;
  controller.subscribe(() => fired++);

  await controller.beginRotation(
    asRawDekBytes(bytesFromRange(32, (i) => i + 100)),
  );
  assert.equal(fired, 1);
});

test("completeRotationSession: destroys the previous handle and clears getPreviousCryptoHandle(), keeps the current one intact", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  await controller.beginRotation(
    asRawDekBytes(bytesFromRange(32, (i) => i + 100)),
  );
  const currentHandle = controller.getCryptoHandle();
  assert.notEqual(controller.getPreviousCryptoHandle(), null);

  controller.completeRotationSession();

  assert.equal(controller.getPreviousCryptoHandle(), null);
  assert.equal(
    controller.getCryptoHandle(),
    currentHandle,
    "the current (new) handle must survive completeRotationSession — only the old one is torn down",
  );
});

test("completeRotationSession: idempotent — calling it with no rotation in progress is a no-op", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  const currentHandle = controller.getCryptoHandle();

  controller.completeRotationSession();

  assert.equal(controller.getPreviousCryptoHandle(), null);
  assert.equal(controller.getCryptoHandle(), currentHandle);
});

test("lock: also clears getPreviousCryptoHandle() — a locked session must never leak a stale rotation candidate", async () => {
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage: memoryWrapStorage(),
    createHandle: testCreateHandle,
  });
  await controller.setDek(
    "user-1",
    asRawDekBytes(bytesFromRange(32, (i) => i)),
  );
  await controller.beginRotation(
    asRawDekBytes(bytesFromRange(32, (i) => i + 100)),
  );
  assert.notEqual(controller.getPreviousCryptoHandle(), null);

  controller.lock();

  assert.equal(controller.getPreviousCryptoHandle(), null);
});

test("checkSetupNeeded: a different uid must never reuse a handle unlocked for someone else", async () => {
  const storage = memoryWrapStorage();
  const controller = createPasskeyDekController({
    provider: fakeWebauthnProvider(),
    recovery: fakeMnemonicRecovery(),
    storage,
    createHandle: testCreateHandle,
  });

  // user-a unlocks (e.g. via setDek, the dev/test injection path).
  await controller.setDek(
    "user-a",
    asRawDekBytes(bytesFromRange(32, (i) => i + 7)),
  );
  assert.notEqual(controller.getCryptoHandle(), null);
  assert.equal(controller.getUserId(), "user-a");

  // A session swap to user-b happens underneath (e.g. multi-tab session sync
  // via BroadcastChannel — another tab of the same browser/origin logs in as
  // a different user, no reload, no intermediate SIGNED_OUT). The consuming
  // app always re-runs checkSetupNeeded(auth.userId) on identity change — the
  // controller itself must refuse to answer for user-b using user-a's handle.
  await controller.checkSetupNeeded("user-b");

  assert.equal(
    controller.getCryptoHandle(),
    null,
    "user-a's handle must be destroyed, not silently reused for user-b",
  );
  assert.equal(controller.getUserId(), null);
});
