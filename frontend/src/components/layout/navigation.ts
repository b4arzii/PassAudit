import {
  FileSpreadsheet,
  LayoutDashboard,
  Palette,
  ScrollText,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Match only this exact path (used for "/"). */
  end?: boolean;
}

export interface NavGroup {
  label: string;
  items: readonly NavItem[];
}

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    label: 'Workspace',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
      { to: '/audit', label: 'Audit', icon: ShieldCheck },
      { to: '/batch', label: 'Batch', icon: FileSpreadsheet },
      { to: '/policies', label: 'Policies', icon: ScrollText },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/design-system', label: 'Design system', icon: Palette },
    ],
  },
];

export const APP_NAME = 'PassAudit';

/** Page titles for the document title, breadcrumb and route announcements. */
export const PAGE_TITLES: Readonly<Record<string, string>> = Object.fromEntries(
  NAV_GROUPS.flatMap((group) => group.items.map((item) => [item.to, item.label])),
);

export function pageTitle(pathname: string): string {
  const normalised = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  return PAGE_TITLES[normalised] ?? 'Page not found';
}
