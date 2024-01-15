import { performance } from "perf_hooks";

export async function stall(ms: number, start: number): Promise<void> {
  const now = performance.now();
  const timeElapsed = now - start;
  const timeRemaining = ms - timeElapsed;

  if (timeRemaining <= 0) return;

  return new Promise((resolve) => setTimeout(resolve, timeRemaining));
}
