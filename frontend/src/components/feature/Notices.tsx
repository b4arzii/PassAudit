import { ScrollText } from 'lucide-react';
import { Link } from 'react-router-dom';

import { DEFAULT_POLICY, POLICY_FIELDS } from '../../lib/policy.ts';
import { plural } from '../../lib/format.ts';
import { useApiStatus } from '../../state/api.ts';
import { usePolicy } from '../../state/policyState.ts';
import { Alert, Button, buttonClasses } from '../ui/index.ts';

/** Shown on workspace pages while the backend is unreachable, with a way to re-check. */
export function ConnectionNotice() {
  const status = useApiStatus();
  if (status.state !== 'offline') return null;
  return (
    <Alert
      tone="warning"
      title="The PassAudit service is not reachable"
      action={
        <Button size="sm" variant="outline" onClick={status.refresh}>
          Check again
        </Button>
      }
    >
      Start the backend with <code className="font-mono">.\scripts\dev.ps1 -Only backend</code>.
      Nothing you type is sent anywhere else.
    </Alert>
  );
}

/** A one-line reminder of which policy applies, linking to where it is edited. */
export function PolicyNotice() {
  const { policy, customised } = usePolicy();
  const changed = POLICY_FIELDS.filter((key) => policy[key] !== DEFAULT_POLICY[key]).length;
  return (
    <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-fg-muted">
      <ScrollText aria-hidden="true" className="size-4 shrink-0 text-secondary" />
      <span>
        Policy:{' '}
        <strong className="font-semibold text-fg">{customised ? 'Custom' : 'Default'}</strong>
        {customised ? ` (${plural(changed, 'rule')} changed)` : ''}
      </span>
      <Link to="/policies" className={buttonClasses({ variant: 'ghost', size: 'sm' })}>
        Edit policy
      </Link>
    </p>
  );
}
