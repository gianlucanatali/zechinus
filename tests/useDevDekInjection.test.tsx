/**
 * Tests the React binding (`useDevDekInjection`). Needs jsdom + React rendering —
 * runs under Vitest (`npm run test:components`), unlike the rest of datacloak/'s
 * tests which run under plain `node --test` (see config/vitest.config.ts).
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { cleanup, render, act, waitFor } from "@testing-library/react";
import type { PasskeyDekController } from "../adapters/passkeyDekController.ts";
import { useDevDekInjection } from "../react/useDevDekInjection.ts";

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  delete (window as unknown as Record<string, unknown>).__setTestDek;
  delete (window as unknown as Record<string, unknown>).__clearTestDek;
});

function fakeController(): PasskeyDekController & {
  setDekCalls: Array<{ userId: string; bytes: Uint8Array }>;
  lockCalls: number;
} {
  const setDekCalls: Array<{ userId: string; bytes: Uint8Array }> = [];
  let lockCalls = 0;
  return {
    setDekCalls,
    get lockCalls() {
      return lockCalls;
    },
    getCryptoHandle: () => null,
    getUserId: () => null,
    getSetupStatus: () => "done",
    getUnlockMethod: () => null,
    getUnlockCredentialId: () => null,
    getDevicePublicKey: () => null,
    getPreviousCryptoHandle: () => null,
    subscribe: () => () => {},
    setDek: async (userId, rawBytes) => {
      setDekCalls.push({ userId, bytes: new Uint8Array(rawBytes) });
    },
    lock: () => {
      lockCalls += 1;
    },
    checkSetupNeeded: async () => {},
    markSetupDone: () => {},
    unlockWithPasskey: async () => {},
    unlockWithRecovery: async () => {},
    registerPasskey: async () => {
      throw new Error("not used in this test");
    },
    addPasskeyToExistingDek: async () => {
      throw new Error("not used in this test");
    },
    regenerateRecoveryWords: async () => {
      throw new Error("not used in this test");
    },
    beginRotation: async () => {
      throw new Error("not used in this test");
    },
    completeRotationSession: () => {},
    wrapCurrentDekForDevice: async () => {
      throw new Error("not used in this test");
    },
  } as PasskeyDekController & {
    setDekCalls: Array<{ userId: string; bytes: Uint8Array }>;
    lockCalls: number;
  };
}

function Harness({
  controller,
  userId,
  cryptoHandle,
  enabled,
  onLock,
}: {
  controller: PasskeyDekController;
  userId: string | null;
  cryptoHandle: unknown;
  enabled: boolean;
  onLock?: () => void;
}) {
  useDevDekInjection(controller, userId, cryptoHandle as never, {
    enabled,
    onLock,
  });
  return null;
}

const w = () => window as unknown as Record<string, unknown>;

describe("useDevDekInjection", () => {
  it("does not register any window hook when disabled", () => {
    render(
      <Harness
        controller={fakeController()}
        userId="user-1"
        cryptoHandle={null}
        enabled={false}
      />,
    );
    expect(w().__setTestDek).toBeUndefined();
    expect(w().__clearTestDek).toBeUndefined();
  });

  it("registers window.__setTestDek when enabled, which sets the DEK on the controller", async () => {
    const controller = fakeController();
    render(
      <Harness
        controller={controller}
        userId="user-1"
        cryptoHandle={null}
        enabled={true}
      />,
    );
    expect(typeof w().__setTestDek).toBe("function");

    await act(async () => {
      await (w().__setTestDek as (hex: string) => Promise<void>)("aabbcc");
    });

    expect(controller.setDekCalls).toHaveLength(1);
    expect(controller.setDekCalls[0].userId).toBe("user-1");
    expect([...controller.setDekCalls[0].bytes]).toEqual([0xaa, 0xbb, 0xcc]);
    expect(sessionStorage.getItem("__testDek__")).toBe(
      JSON.stringify([0xaa, 0xbb, 0xcc]),
    );
  });

  it("__setTestDek throws when there is no active user id", async () => {
    const controller = fakeController();
    render(
      <Harness
        controller={controller}
        userId={null}
        cryptoHandle={null}
        enabled={true}
      />,
    );
    await expect(
      (w().__setTestDek as (hex: string) => Promise<void>)("aabbcc"),
    ).rejects.toThrow();
    expect(controller.setDekCalls).toHaveLength(0);
  });

  it("__clearTestDek locks the controller, clears storage, and calls onLock", () => {
    const controller = fakeController();
    sessionStorage.setItem("__testDek__", JSON.stringify([1, 2, 3]));
    const onLock = vi.fn();
    render(
      <Harness
        controller={controller}
        userId="user-1"
        cryptoHandle={null}
        enabled={true}
        onLock={onLock}
      />,
    );

    (w().__clearTestDek as () => void)();

    expect(controller.lockCalls).toBe(1);
    expect(sessionStorage.getItem("__testDek__")).toBeNull();
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("restores a stored test DEK on mount when no cryptoHandle is active yet", async () => {
    sessionStorage.setItem("__testDek__", JSON.stringify([9, 8, 7]));
    const controller = fakeController();
    render(
      <Harness
        controller={controller}
        userId="user-1"
        cryptoHandle={null}
        enabled={true}
      />,
    );

    await waitFor(() => expect(controller.setDekCalls).toHaveLength(1));
    expect(controller.setDekCalls[0].userId).toBe("user-1");
    expect([...controller.setDekCalls[0].bytes]).toEqual([9, 8, 7]);
  });

  it("does not restore a stored test DEK once a cryptoHandle is already active", async () => {
    sessionStorage.setItem("__testDek__", JSON.stringify([9, 8, 7]));
    const controller = fakeController();
    render(
      <Harness
        controller={controller}
        userId="user-1"
        cryptoHandle={{ some: "handle" }}
        enabled={true}
      />,
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(controller.setDekCalls).toHaveLength(0);
  });

  it("removes the window hooks on unmount", () => {
    const { unmount } = render(
      <Harness
        controller={fakeController()}
        userId="user-1"
        cryptoHandle={null}
        enabled={true}
      />,
    );
    expect(typeof w().__setTestDek).toBe("function");
    unmount();
    expect(w().__setTestDek).toBeUndefined();
    expect(w().__clearTestDek).toBeUndefined();
  });
});
