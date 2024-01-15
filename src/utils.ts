import { performance } from "perf_hooks";
import ms from "ms";

export async function stall(ms: number, start: number): Promise<void> {
  const now = performance.now();
  const timeElapsed = now - start;
  const timeRemaining = ms - timeElapsed;

  if (timeRemaining <= 0) return;

  return new Promise((resolve) => setTimeout(resolve, timeRemaining));
}

export function getMilliseconds<T>(value: unknown, fallback?: T): number | T;
export function getMilliseconds(
  value: unknown,
  fallback = undefined
): number | undefined {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    value === ""
  ) {
    return fallback;
  }

  return ms(String(value)) ?? fallback;
}
