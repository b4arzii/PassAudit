import { Skeleton, SkeletonText } from '../ui/index.ts';

/** Shown while a lazily loaded page is fetched. Busy for assistive technology, silent otherwise. */
export function PageLoading() {
  return (
    <div aria-busy="true" className="space-y-6">
      <span role="status" className="sr-only">
        Loading page
      </span>
      <Skeleton className="h-10 w-64" />
      <SkeletonText lines={2} />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Skeleton className="h-40 rounded-2xl" />
        <Skeleton className="h-40 rounded-2xl" />
        <Skeleton className="h-40 rounded-2xl" />
      </div>
    </div>
  );
}
