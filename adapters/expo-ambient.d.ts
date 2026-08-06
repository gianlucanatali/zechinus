/**
 * Minimal ambient type declarations for expo-secure-store/expo-file-system —
 * real peer packages a consuming React Native app provides, never a dependency
 * of this package itself (see expoDeviceCacheStorage.ts's own file-level doc
 * comment: this file only exists so `npm run build` can type-check and compile
 * expoDeviceCacheStorage.ts without those packages actually installed here.
 * `any`-typed on purpose — the real, precise types come from the consumer's
 * own `expo-secure-store`/`expo-file-system` installation at their build time;
 * this file's only job is letting OUR build emit valid JS, not modeling their
 * full API surface.
 */
declare module "expo-secure-store" {
  export function getItemAsync(key: string, options?: any): Promise<string | null>;
  export function setItemAsync(key: string, value: string, options?: any): Promise<void>;
  export function deleteItemAsync(key: string, options?: any): Promise<void>;
}

declare module "expo-file-system" {
  export class Directory {
    constructor(...args: any[]);
    [key: string]: any;
  }
  export class File {
    constructor(...args: any[]);
    [key: string]: any;
  }
  export const Paths: any;
}
