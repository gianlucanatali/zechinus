/**
 * Web Worker isolation for a `KeyHandle` — the raw key bytes live only inside the
 * Worker, never on the main thread (so a compromised extension or a XSS on the main
 * thread can't read them). Any web app doing zero-knowledge E2E encryption wants this
 * same isolation, and the request/response message protocol is entirely generic —
 * this is that protocol, both directions.
 *
 * What stays app-side: constructing the actual `Worker` (`new Worker(new URL(...))`
 * needs a literal, statically analyzable path for bundlers like Vite — can't be
 * parametrized through a shared module) and which `KeyHandle` factory the worker-side
 * calls (e.g. `createDekHandle` with the app's own salts). Both are 2-3 line files
 * that just wire the app's specifics into these two functions.
 */
import type {
  KeyHandle,
  WrappedKey,
  RawDekBytes,
} from "../../core/keyDerivation.ts";
import type { FieldAAD, EncryptedField } from "../../core/types.ts";

export interface WorkerLike {
  postMessage(data: unknown): void;
  addEventListener(type: "message", cb: (e: { data: unknown }) => void): void;
  terminate(): void;
}

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

/**
 * Main-thread side: spawns the request/response protocol against an already-
 * constructed `Worker`, returning a `KeyHandle` proxy — every method sends a message
 * and awaits the reply. The raw key bytes are sent once (`init`) and never returned.
 */
export async function createWorkerKeyHandle(
  worker: WorkerLike,
  rawBytes: RawDekBytes,
): Promise<KeyHandle> {
  let nextId = 0;
  const pending = new Map<number, Pending>();

  worker.addEventListener("message", (e: { data: unknown }) => {
    const msg = e.data as {
      id: number;
      ok: boolean;
      result?: unknown;
      error?: string;
    };
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.ok) p.resolve(msg.result);
    else p.reject(new Error(msg.error));
  });

  function send(
    type: string,
    args: Record<string, unknown> = {},
  ): Promise<unknown> {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, type, ...args });
    });
  }

  const { pid } = (await send("init", { rawBytes })) as { pid: string };

  return {
    pid,
    encryptField: (plaintext, aad) =>
      send("encryptField", { plaintext, aad }) as Promise<EncryptedField>,
    decryptField: (enc, aad) =>
      send("decryptField", { enc, aad }) as Promise<string>,
    encryptJson: <T>(value: T, aad: FieldAAD) =>
      send("encryptJson", { value, aad }) as Promise<EncryptedField>,
    decryptJson: <T>(enc: EncryptedField, aad: FieldAAD) =>
      send("decryptJson", { enc, aad }) as Promise<T>,
    hashContent: (payload: unknown) =>
      send("hashContent", { payload }) as Promise<string>,
    wrapWithKek: (kek) => send("wrapWithKek", { kek }) as Promise<WrappedKey>,
    wrapForDevice: (devicePublicKeyB64) =>
      send("wrapForDevice", { devicePublicKeyB64 }) as Promise<{
        ciphertext: string;
        nonce: string;
        ephemeralPublicKeyB64: string;
      }>,
    destroy() {
      worker.postMessage({ id: nextId++, type: "destroy" });
      worker.terminate();
    },
  };
}

export interface WorkerContext {
  postMessage(data: unknown): void;
  addEventListener(type: "message", cb: (e: { data: unknown }) => void): void;
}

type Req = { id: number; type: string } & Record<string, unknown>;

/**
 * Worker-side of the protocol: listens for requests, dispatches them against a
 * `KeyHandle` built (once, on `init`) by the given factory, replies with the result
 * or an error. Call this from the actual worker entry file, e.g.:
 * `handleKeyHandleMessages((rawBytes) => createDekHandle(rawBytes), self)`.
 */
export function handleKeyHandleMessages(
  createHandle: (rawBytes: RawDekBytes) => KeyHandle,
  ctx: WorkerContext,
): void {
  let cryptoHandle: KeyHandle | null = null;

  ctx.addEventListener("message", async (e: { data: unknown }) => {
    const { id, type, ...args } = e.data as Req;
    try {
      let result: unknown = null;
      switch (type) {
        case "init":
          cryptoHandle = createHandle(args.rawBytes as RawDekBytes);
          result = { pid: cryptoHandle.pid };
          break;
        case "encryptField":
          result = await cryptoHandle!.encryptField(
            args.plaintext as string,
            args.aad as FieldAAD,
          );
          break;
        case "decryptField":
          result = await cryptoHandle!.decryptField(
            args.enc as EncryptedField,
            args.aad as FieldAAD,
          );
          break;
        case "encryptJson":
          result = await cryptoHandle!.encryptJson(
            args.value,
            args.aad as FieldAAD,
          );
          break;
        case "decryptJson":
          result = await cryptoHandle!.decryptJson(
            args.enc as EncryptedField,
            args.aad as FieldAAD,
          );
          break;
        case "hashContent":
          if (!cryptoHandle!.hashContent) {
            throw new Error(
              "workerKeyHandle: the underlying KeyHandle has no hashContent — cannot proxy it through the worker.",
            );
          }
          result = await cryptoHandle!.hashContent(args.payload);
          break;
        case "wrapWithKek":
          result = await cryptoHandle!.wrapWithKek(args.kek as Uint8Array);
          break;
        case "wrapForDevice":
          if (!cryptoHandle!.wrapForDevice) {
            throw new Error(
              "workerKeyHandle: the underlying KeyHandle has no wrapForDevice — cannot proxy it through the worker.",
            );
          }
          result = await cryptoHandle!.wrapForDevice(
            args.devicePublicKeyB64 as string,
          );
          break;
        case "destroy":
          cryptoHandle?.destroy();
          cryptoHandle = null;
          break;
        default:
          throw new Error(`workerKeyHandle: unknown message type: ${type}`);
      }
      ctx.postMessage({ id, ok: true, result });
    } catch (err) {
      ctx.postMessage({ id, ok: false, error: String(err) });
    }
  });
}
