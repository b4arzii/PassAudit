import { Menu, ShieldCheck } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

import { Badge } from '../ui/Badge.tsx';
import { IconButton } from '../ui/Button.tsx';
import { ConnectionBadge } from './ConnectionBadge.tsx';
import { APP_NAME, pageTitle } from './navigation.ts';
import { ThemeToggle } from './ThemeToggle.tsx';

export interface HeaderProps {
  onOpenMenu: () => void;
  menuOpen: boolean;
  menuId: string;
}

/** Sticky glass header: menu button (small screens), breadcrumb, status and theme toggle. */
export function Header({ onOpenMenu, menuOpen, menuId }: HeaderProps) {
  const { pathname } = useLocation();
  const title = pageTitle(pathname);
  const atRoot = pathname === '/';

  return (
    <header className="glass sticky top-0 z-30 rounded-none border-x-0 border-t-0">
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-3 px-4 sm:px-6 lg:px-10">
        <IconButton
          label="Open navigation menu"
          className="-ml-2 lg:hidden"
          aria-expanded={menuOpen}
          aria-controls={menuId}
          aria-haspopup="dialog"
          onClick={onOpenMenu}
        >
          <Menu aria-hidden="true" className="size-5" />
        </IconButton>

        <nav aria-label="Breadcrumb" className="min-w-0 flex-1">
          <ol className="flex items-center gap-2 text-sm">
            <li className="hidden sm:block">
              <Link to="/" className="rounded text-fg-muted transition-colors hover:text-fg">
                {APP_NAME}
              </Link>
            </li>
            <li aria-hidden="true" className="hidden text-fg-subtle sm:block">
              /
            </li>
            <li className="truncate font-medium text-fg" aria-current={atRoot ? undefined : 'page'}>
              {atRoot ? 'Overview' : title}
            </li>
          </ol>
        </nav>

        <Badge
          tone="primary"
          size="sm"
          dot
          icon={<ShieldCheck aria-hidden="true" className="size-3.5" />}
          className="hidden md:inline-flex"
          title="The service listens on this machine only (127.0.0.1)"
        >
          Local only
        </Badge>
        <ConnectionBadge />
        <ThemeToggle />
      </div>
    </header>
  );
}
