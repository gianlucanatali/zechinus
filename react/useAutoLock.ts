/**
 * Auto-lock on inactivity — any app holding a decrypted key material in memory
 * (a `KeyHandle`) wants to destroy it after N ms without user interaction, so a
 * forgotten open tab doesn't leave the vault unlocked indefinitely. The mechanism
 * (listen for activity, reset a timer, call back on timeout) is identical
 * regardless of the app; only the timeout value and what "lock" means are the
 * app's business, so both are passed in rather than assumed here.
 */
import { useEffect } from "react";

const ACTIVITY_EVENTS = [
  "mousemove",
  "keydown",
  "click",
  "touchstart",
  "scroll",
] as const;

/**
 * @param active Whether the timer should be running at all (e.g. a key is
 *   currently unlocked). When `false`, no timer is set and no listeners attach.
 * @param onTimeout Called once when `ms` elapse without any activity event.
 * @param ms Inactivity timeout in milliseconds.
 */
export function useAutoLock(
  active: boolean,
  onTimeout: () => void,
  ms: number,
): void {
  useEffect(() => {
    if (!active) return;
    let timer: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(onTimeout, ms);
    };
    ACTIVITY_EVENTS.forEach((event) =>
      window.addEventListener(event, reset, { passive: true }),
    );
    reset();
    return () => {
      clearTimeout(timer);
      ACTIVITY_EVENTS.forEach((event) =>
        window.removeEventListener(event, reset),
      );
    };
  }, [active, onTimeout, ms]);
}
