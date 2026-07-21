/**
 * Minimal ambient types so tsc accepts bun:test without installing @types/bun.
 */

declare module 'bun:test' {
  interface ExpectMatchers {
    toBe(expected: unknown): void;
    toContain(expected: unknown): void;
    toMatch(expected: RegExp | string): void;
    toBeUndefined(): void;
    toBeTruthy(): void;
    not: ExpectMatchers;
  }

  export function describe(name: string, fn: () => void): void;
  export function test(name: string, fn: () => void | Promise<void>): void;
  export function expect(actual: unknown): ExpectMatchers;
}
