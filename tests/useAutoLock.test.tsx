/**
 * Tests the React binding (`useAutoLock`). Needs jsdom + React rendering — runs
 * under Vitest (`npm run test:components`), unlike the rest of datacloak/'s tests
 * which run under plain `node --test` (see config/vitest.config.ts).
 */
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { cleanup, render, act } from "@testing-library/react";
import { useAutoLock } from "../react/useAutoLock.ts";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

beforeEach(() => {
  vi.useFakeTimers();
});

function Harness({
  active,
  ms,
  onTimeout,
}: {
  active: boolean;
  ms: number;
  onTimeout: () => void;
}) {
  useAutoLock(active, onTimeout, ms);
  return null;
}

describe("useAutoLock", () => {
  it("calls onTimeout after `ms` of inactivity when active", () => {
    const onTimeout = vi.fn();
    render(<Harness active={true} ms={1000} onTimeout={onTimeout} />);

    act(() => vi.advanceTimersByTime(999));
    expect(onTimeout).not.toHaveBeenCalled();

    act(() => vi.advanceTimersByTime(1));
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it("resets the timer on activity — no timeout at the original deadline", () => {
    const onTimeout = vi.fn();
    render(<Harness active={true} ms={1000} onTimeout={onTimeout} />);

    act(() => vi.advanceTimersByTime(600));
    act(() => window.dispatchEvent(new Event("mousemove")));
    act(() => vi.advanceTimersByTime(600));
    // 1200ms elapsed total, but the reset at 600ms pushed the deadline to 1600ms.
    expect(onTimeout).not.toHaveBeenCalled();

    act(() => vi.advanceTimersByTime(400));
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it("never fires when inactive, regardless of elapsed time", () => {
    const onTimeout = vi.fn();
    render(<Harness active={false} ms={1000} onTimeout={onTimeout} />);

    act(() => vi.advanceTimersByTime(10_000));
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("stops listening and clears the timer on unmount (no late call)", () => {
    const onTimeout = vi.fn();
    const { unmount } = render(
      <Harness active={true} ms={1000} onTimeout={onTimeout} />,
    );
    unmount();

    act(() => vi.advanceTimersByTime(10_000));
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("stops the previous timer when `active` flips to false mid-countdown", () => {
    const onTimeout = vi.fn();
    const { rerender } = render(
      <Harness active={true} ms={1000} onTimeout={onTimeout} />,
    );
    act(() => vi.advanceTimersByTime(500));
    rerender(<Harness active={false} ms={1000} onTimeout={onTimeout} />);

    act(() => vi.advanceTimersByTime(10_000));
    expect(onTimeout).not.toHaveBeenCalled();
  });
});
