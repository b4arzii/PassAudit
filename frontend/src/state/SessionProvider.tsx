import { useCallback, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

import { MAX_RUNS, SessionContext } from './session.ts';
import type { NewRun, SessionRun, SessionValue } from './session.ts';

export function SessionProvider({ children }: { children: ReactNode }) {
  const [runs, setRuns] = useState<readonly SessionRun[]>([]);
  const counter = useRef(0);

  const addRun = useCallback((run: NewRun): string => {
    counter.current += 1;
    const id = `run-${String(counter.current)}`;
    const record: SessionRun = { ...run, id, at: new Date().toISOString(), source: 'live' };
    setRuns((current) => [record, ...current].slice(0, MAX_RUNS)); // bounded memory
    return id;
  }, []);

  const clear = useCallback(() => {
    setRuns([]);
  }, []);

  const value = useMemo<SessionValue>(
    () => ({ runs, records: runs.flatMap((r) => r.records), addRun, clear }),
    [runs, addRun, clear],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
