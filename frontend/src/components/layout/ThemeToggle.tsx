import { Moon, Sun } from 'lucide-react';

import { useTheme } from '../../theme/useTheme.ts';
import { IconButton } from '../ui/Button.tsx';

/** One-click light/dark switch for the header. (Settings offers the full light/dark/system choice.) */
export function ThemeToggle() {
  const { resolved, toggle } = useTheme();
  const next = resolved === 'dark' ? 'light' : 'dark';
  return (
    <IconButton label={`Switch to ${next} theme`} onClick={toggle}>
      {resolved === 'dark' ? (
        <Sun aria-hidden="true" className="size-5" />
      ) : (
        <Moon aria-hidden="true" className="size-5" />
      )}
    </IconButton>
  );
}
