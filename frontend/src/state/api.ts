import { createContext, useContext } from 'react';

import type { ApiClient } from '../api/client.ts';
import type { CapabilitiesResponse, LimitsResponse } from '../api/types.ts';

export type ConnectionState = 'checking' | 'online' | 'offline';

export interface ApiStatus {
  state: ConnectionState;
  /** Backend version, when connected. */
  version: string | null;
  /** The server's limits when known, otherwise the documented defaults. */
  limits: LimitsResponse;
  /** True when `limits` came from the server rather than the fallback. */
  limitsLive: boolean;
  /** Optional server features (breach checks, reuse index, profiles). `null` until known. */
  capabilities: CapabilitiesResponse | null;
  checkedAt: Date | null;
  refresh: () => void;
}

/** Documented defaults (docs/api.md), used for validation while the backend is unknown. */
export const FALLBACK_LIMITS: LimitsResponse = {
  max_password_length: 1024,
  max_body_bytes: 65536,
  batch_max_items: 50,
  batch_max_body_bytes: 1048576,
  max_personal_info_items: 50,
  max_personal_info_item_length: 256,
  rate_limit: { enabled: true, burst: 100, refill_per_minute: 300, cost_per_password: 1 },
};

export interface ApiContextValue {
  client: ApiClient;
  status: ApiStatus;
}

export const ApiContext = createContext<ApiContextValue | null>(null);

function useApiContext(): ApiContextValue {
  const value = useContext(ApiContext);
  if (!value) throw new Error('useApi / useApiStatus must be used inside <ApiProvider>');
  return value;
}

/** The API client (injectable in tests). */
export function useApi(): ApiClient {
  return useApiContext().client;
}

export function useApiStatus(): ApiStatus {
  return useApiContext().status;
}
