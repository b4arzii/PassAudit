import { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';

import type { ApiClient } from './api/client.ts';
import { AppShell } from './components/layout/AppShell.tsx';
import { PageLoading } from './components/layout/PageLoading.tsx';
import { ToastProvider } from './components/ui/index.ts';
import AuditPage from './pages/AuditPage.tsx';
import BatchPage from './pages/BatchPage.tsx';
import NotFound from './pages/NotFound.tsx';
import Overview from './pages/Overview.tsx';
import PoliciesPage from './pages/PoliciesPage.tsx';
import Settings from './pages/Settings.tsx';
import { ApiProvider } from './state/ApiProvider.tsx';
import { PolicyProvider } from './state/PolicyProvider.tsx';
import { PreferencesProvider } from './state/PreferencesProvider.tsx';
import { SessionProvider } from './state/SessionProvider.tsx';
import { ThemeProvider } from './theme/ThemeProvider.tsx';

// The design-system gallery is large and rarely visited: load it on demand.
const DesignSystem = lazy(() => import('./pages/DesignSystem.tsx'));

export interface AppProps {
  /** Tests inject a client; the app uses the shared one. */
  client?: ApiClient;
}

/** Providers and routes. The router itself is supplied by the caller (BrowserRouter / tests). */
export default function App({ client }: AppProps) {
  return (
    <ThemeProvider>
      <ToastProvider>
        <PreferencesProvider>
          <ApiProvider {...(client ? { client } : {})}>
            <PolicyProvider>
              <SessionProvider>
                <Routes>
                  <Route element={<AppShell version={__APP_VERSION__} />}>
                    <Route index element={<Overview />} />
                    <Route path="audit" element={<AuditPage />} />
                    <Route path="batch" element={<BatchPage />} />
                    <Route path="policies" element={<PoliciesPage />} />
                    <Route path="settings" element={<Settings version={__APP_VERSION__} />} />
                    <Route
                      path="design-system"
                      element={
                        <Suspense fallback={<PageLoading />}>
                          <DesignSystem />
                        </Suspense>
                      }
                    />
                    <Route path="*" element={<NotFound />} />
                  </Route>
                </Routes>
              </SessionProvider>
            </PolicyProvider>
          </ApiProvider>
        </PreferencesProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}
