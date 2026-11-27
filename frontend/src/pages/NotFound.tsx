import { Compass } from 'lucide-react';
import { Link } from 'react-router-dom';

import { EmptyState, PageHeader, buttonClasses } from '../components/ui/index.ts';

export default function NotFound() {
  return (
    <div>
      <PageHeader eyebrow="404" title="Page not found" />
      <EmptyState
        icon={<Compass className="size-6" />}
        title="We could not find that page"
        description="The address may be mistyped, or the page may have moved."
        action={
          <Link to="/" className={buttonClasses()}>
            Back to the overview
          </Link>
        }
      />
    </div>
  );
}
