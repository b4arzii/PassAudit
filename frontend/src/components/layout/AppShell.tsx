import { useCallback, useEffect, useRef, useState } from 'react';
import { Outlet } from 'react-router-dom';

import { cn } from '../../lib/cn.ts';
import { usePersistentBoolean } from '../../lib/usePersistentState.ts';
import { Overlay } from '../ui/Overlay.tsx';
import { Header } from './Header.tsx';
import { RouteAnnouncer } from './RouteAnnouncer.tsx';
import { SIDEBAR_WIDTH, SIDEBAR_WIDTH_COLLAPSED, SidebarContent } from './Sidebar.tsx';

const MOBILE_NAV_ID = 'mobile-navigation';
const DESKTOP_QUERY = '(min-width: 1024px)';

export const SIDEBAR_STORAGE_KEY = 'passaudit.sidebar-collapsed';

/**
 * The application frame.
 *
 * Landmarks: skip link, `<header>`, `<nav>` (sidebar / drawer), `<main id="main">`,
 * `<footer>`. Large screens get a persistent sidebar that can collapse to icons; smaller
 * screens get a header menu button that opens the same navigation in a modal drawer.
 */
export function AppShell({ version }: { version: string }) {
  const [collapsed, setCollapsed] = usePersistentBoolean(SIDEBAR_STORAGE_KEY, false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
  }, []);

  // A drawer left open while the window is widened would trap focus behind a visible sidebar.
  useEffect(() => {
    if (!drawerOpen || typeof window.matchMedia !== 'function') return;
    const query = window.matchMedia(DESKTOP_QUERY);
    const onChange = () => {
      if (query.matches) setDrawerOpen(false);
    };
    query.addEventListener('change', onChange);
    return () => {
      query.removeEventListener('change', onChange);
    };
  }, [drawerOpen]);

  return (
    <div className="bg-ambient relative min-h-dvh">
      <a
        href="#main"
        className="skip-link"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to main content
      </a>

      {/* Desktop rail */}
      <aside
        className="glass fixed inset-y-0 left-0 z-40 hidden rounded-none border-y-0 border-l-0 transition-[width] duration-200 motion-reduce:transition-none lg:block"
        style={{ width: collapsed ? SIDEBAR_WIDTH_COLLAPSED : SIDEBAR_WIDTH }}
      >
        <SidebarContent
          collapsed={collapsed}
          onToggleCollapsed={() => {
            setCollapsed(!collapsed);
          }}
          version={version}
        />
      </aside>

      {/* Mobile drawer */}
      <Overlay
        open={drawerOpen}
        onClose={closeDrawer}
        ariaLabel="Navigation menu"
        placement="left"
        panelClassName="!rounded-l-none"
      >
        <SidebarContent onNavigate={closeDrawer} version={version} navId={MOBILE_NAV_ID} />
      </Overlay>

      <div
        className={cn(
          'relative z-10 flex min-h-dvh flex-col transition-[padding] duration-200 motion-reduce:transition-none',
          collapsed ? 'lg:pl-[76px]' : 'lg:pl-[264px]',
        )}
      >
        <Header
          onOpenMenu={() => {
            setDrawerOpen(true);
          }}
          menuOpen={drawerOpen}
          menuId={MOBILE_NAV_ID}
        />
        <main
          id="main"
          ref={mainRef}
          tabIndex={-1}
          className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 outline-none sm:px-6 sm:py-10 lg:px-10"
        >
          <Outlet />
        </main>
        <footer className="mx-auto w-full max-w-7xl px-4 pb-8 pt-4 text-xs text-fg-subtle sm:px-6 lg:px-10">
          <p>
            PassAudit v{version} - runs locally. Passwords are never stored, logged or transmitted
            to third parties.
          </p>
        </footer>
      </div>

      <RouteAnnouncer mainRef={mainRef} />
    </div>
  );
}
