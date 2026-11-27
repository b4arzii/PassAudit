import { useCallback, useEffect, useRef, useState } from 'react';

export type ActionState<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: T }
  | { status: 'error'; error: unknown };

export interface AsyncAction<T> {
  state: ActionState<T>;
  /**
   * Run `task`. A newer run (or `cancel`, or unmounting) aborts the previous one and its result
   * is dropped, so a slow stale response can never overwrite a newer one. Resolves with the
   * data, or `undefined` on failure / cancellation (the failure is in `state`).
   */
  run: (task: (signal: AbortSignal) => Promise<T>) => Promise<T | undefined>;
  /** Abort anything in flight and return to idle. */
  cancel: () => void;
}

/**
 * Loading / success / error state for one API call. It stores only what the call returns (or
 * the error) - never the request - so a password captured in `task`'s closure is not retained
 * by this hook once the call settles.
 */
export function useAsyncAction<T>(): AsyncAction<T> {
  const [state, setState] = useState<ActionState<T>>({ status: 'idle' });
  const current = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      current.current?.abort();
    },
    [],
  );

  const run = useCallback(async (task: (signal: AbortSignal) => Promise<T>) => {
    current.current?.abort();
    const controller = new AbortController();
    current.current = controller;
    setState({ status: 'loading' });
    try {
      const data = await task(controller.signal);
      if (controller.signal.aborted) return undefined;
      setState({ status: 'success', data });
      return data;
    } catch (error) {
      if (controller.signal.aborted) return undefined;
      setState({ status: 'error', error });
      return undefined;
    }
  }, []);

  const cancel = useCallback(() => {
    current.current?.abort();
    current.current = null;
    setState({ status: 'idle' });
  }, []);

  return { state, run, cancel };
}
