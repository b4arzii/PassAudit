import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { api as defaultClient } from '../api/client.ts';
import type { ApiClient } from '../api/client.ts';
import type { CapabilitiesResponse } from '../api/types.ts';
import { ApiContext, FALLBACK_LIMITS } from './api.ts';
import type { ApiStatus, ConnectionState } from './api.ts';

/**
 * Provides the API client and the live connection status. On mount (and on `refresh()`, and
 * when the browser comes back online) it asks the service for `/health` and `/limits`. It
 * never sends anything user-entered.
 */
export function ApiProvider({
  client = defaultClient,
  children,
}: {
  client?: ApiClient;
  children: ReactNode;
}) {
  const [state, setState] = useState<ConnectionState>('checking');
  const [version, setVersion] = useState<string | null>(null);
  const [limits, setLimits] = useState(FALLBACK_LIMITS);
  const [limitsLive, setLimitsLive] = useState(false);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(() => {
    setState('checking');
    setTick((t) => t + 1);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const health = await client.health(controller.signal);
        setVersion(health.version);
        setState('online');
        try {
          setLimits(await client.limits(controller.signal));
          setLimitsLive(true);
        } catch {
          setLimitsLive(false); // keep the documented defaults
        }
        try {
          setCapabilities(await client.capabilities(controller.signal));
        } catch {
          setCapabilities(null); // an older backend: no optional features are offered
        }
      } catch {
        if (controller.signal.aborted) return;
        setVersion(null);
        setLimitsLive(false);
        setCapabilities(null);
        setState('offline');
      } finally {
        if (!controller.signal.aborted) setCheckedAt(new Date());
      }
    })();
    return () => {
      controller.abort();
    };
  }, [client, tick]);

  useEffect(() => {
    const onOnline = () => {
      refresh();
    };
    window.addEventListener('online', onOnline);
    return () => {
      window.removeEventListener('online', onOnline);
    };
  }, [refresh]);

  const status = useMemo<ApiStatus>(
    () => ({ state, version, limits, limitsLive, capabilities, checkedAt, refresh }),
    [state, version, limits, limitsLive, capabilities, checkedAt, refresh],
  );
  const value = useMemo(() => ({ client, status }), [client, status]);
  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
}
