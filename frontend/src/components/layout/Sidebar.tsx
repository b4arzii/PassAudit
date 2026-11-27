import { LockKeyhole, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { cn } from '../../lib/cn.ts';
import { IconButton } from '../ui/Button.tsx';
import { Logo } from './Logo.tsx';
import { NAV_GROUPS } from './navigation.ts';

export const SIDEBAR_WIDTH = 264;
export const SIDEBAR_WIDTH_COLLAPSED = 76;
export const NAV_ID = 'primary-navigation';

export interface SidebarContentProps {
  collapsed?: boolean;
  /** Called when a link is followed (the mobile drawer closes itself). */
  onNavigate?: () => void;
  /** Show the collapse/expand control (desktop only). */
  onToggleCollapsed?: () => void;
  version: string;
  /** Unique per instance: the desktop rail and the mobile drawer never share an id. */
  navId?: string;
}

/** The sidebar's contents, shared by the desktop rail and the mobile drawer. */
export function SidebarContent({
  collapsed = false,
  onNavigate,
  onToggleCollapsed,
  version,
  navId = NAV_ID,
}: SidebarContentProps) {
  return (
    <div className="flex h-full flex-col">
      <div
        className={cn(
          'flex h-16 shrink-0 items-center border-b border-line/10',
          collapsed ? 'justify-center px-2' : 'justify-between px-5',
        )}
      >
        <NavLink to="/" onClick={onNavigate} aria-label="PassAudit home" className="rounded-lg">
          <Logo showText={!collapsed} />
        </NavLink>
      </div>

      <nav id={navId} aria-label="Primary" className="flex-1 overflow-y-auto px-3 py-4">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-6 last:mb-0">
            <p
              className={cn(
                'mb-2 px-3 text-xs font-semibold uppercase tracking-[0.14em] text-fg-subtle',
                collapsed && 'sr-only',
              )}
            >
              {group.label}
            </p>
            <ul className="space-y-1">
              {group.items.map(({ to, label, icon: Icon, end }) => (
                <li key={to}>
                  <NavLink
                    to={to}
                    end={end ?? false}
                    onClick={onNavigate}
                    title={collapsed ? label : undefined}
                    className={({ isActive }) =>
                      cn(
                        'group relative flex h-11 items-center gap-3 rounded-xl px-3 text-sm font-medium transition-colors',
                        collapsed && 'justify-center px-0',
                        isActive
                          ? 'bg-primary/10 text-fg shadow-[inset_0_0_0_1px_rgb(var(--primary)/0.25)]'
                          : 'text-fg-muted hover:bg-fg/5 hover:text-fg',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span
                            aria-hidden="true"
                            className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-primary shadow-[0_0_12px_rgb(var(--primary))]"
                          />
                        )}
                        <Icon
                          aria-hidden="true"
                          className={cn(
                            'size-5 shrink-0 transition-colors',
                            isActive ? 'text-primary' : 'text-fg-subtle group-hover:text-fg',
                          )}
                        />
                        <span className={cn(collapsed && 'sr-only')}>{label}</span>
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="shrink-0 space-y-3 border-t border-line/10 p-3">
        {!collapsed && (
          <div className="rounded-xl border border-line/10 bg-brand-gradient-soft p-3.5">
            <p className="flex items-center gap-2 text-sm font-semibold text-fg">
              <LockKeyhole aria-hidden="true" className="size-4 text-primary" />
              Local-first
            </p>
            <p className="mt-1 text-xs text-fg-muted">
              Passwords are analysed on this machine and are never sent anywhere.
            </p>
          </div>
        )}
        <div className={cn('flex items-center', collapsed ? 'justify-center' : 'justify-between')}>
          {!collapsed && <span className="px-1 font-mono text-xs text-fg-subtle">v{version}</span>}
          {onToggleCollapsed && (
            <IconButton
              label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              size="sm"
              aria-expanded={!collapsed}
              aria-controls={navId}
              onClick={onToggleCollapsed}
            >
              {collapsed ? (
                <PanelLeftOpen aria-hidden="true" className="size-5" />
              ) : (
                <PanelLeftClose aria-hidden="true" className="size-5" />
              )}
            </IconButton>
          )}
        </div>
      </div>
    </div>
  );
}
