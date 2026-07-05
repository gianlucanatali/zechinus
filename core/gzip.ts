/**
 * Pluggable gzip — the ONE web/Deno-only dependency in the crypto path.
 * `CompressionStream` doesn't exist on React Native/Hermes: such runtimes inject a
 * standard-gzip implementation (e.g. fflate) at bootstrap via `setGzipImpl`.
 * CONTRACT: output must be standard gzip (RFC 1952) — blobs written under one
 * implementation MUST decompress under any other. Never plug a different algorithm.
 */
export interface GzipImpl {
  compress(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
  decompress(data: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

let injected: GzipImpl | null = null;

/** Injects a gzip implementation (or `null` to restore the runtime default). */
export function setGzipImpl(impl: GzipImpl | null): void {
  injected = impl;
}

function requireNativeStreams(): void {
  if (typeof CompressionStream === "undefined") {
    throw new Error(
      "datacloak: no gzip implementation available — this runtime has no " +
        "CompressionStream (React Native/Hermes?). Call setGzipImpl({ compress, " +
        "decompress }) at bootstrap, e.g. backed by fflate.",
    );
  }
}

export async function gzipCompress(data: Uint8Array): Promise<Uint8Array> {
  if (injected) return injected.compress(data);
  requireNativeStreams();
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  writer.write(data as Uint8Array<ArrayBuffer>);
  writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

export async function gzipDecompress(data: Uint8Array): Promise<Uint8Array> {
  if (injected) return injected.decompress(data);
  requireNativeStreams();
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(data as Uint8Array<ArrayBuffer>);
  writer.close();
  return new Uint8Array(await new Response(ds.readable).arrayBuffer());
}
