import { useApiStatus } from '../../state/api.ts';
import { Badge } from '../ui/Badge.tsx';

/** The backend connection at a glance. The text carries the meaning; the dot is decoration. */
export function ConnectionBadge() {
  const { state, version } = useApiStatus();
  if (state === 'online') {
    return (
      <Badge
        tone="success"
        size="sm"
        dot
        title={version ? `PassAudit service v${version}` : undefined}
      >
        Service connected
      </Badge>
    );
  }
  if (state === 'offline') {
    return (
      <Badge tone="warning" size="sm" dot title="The local service could not be reached">
        Service offline
      </Badge>
    );
  }
  return (
    <Badge tone="neutral" size="sm" dot>
      Connecting...
    </Badge>
  );
}
