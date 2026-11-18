import { useRef } from "react";

/** Retain the command identity when an unchanged form is retried after a lost response. */
export function useCommandIdentity() {
  const pending = useRef<{ fingerprint: string; key: string } | undefined>(
    undefined,
  );
  return (route: string, body: unknown) => {
    const fingerprint = JSON.stringify([route, body]);
    if (pending.current?.fingerprint !== fingerprint) {
      pending.current = { fingerprint, key: crypto.randomUUID() };
    }
    return { idempotencyKey: pending.current.key };
  };
}
