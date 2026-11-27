export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

/** The slice of `items` on 1-based `page` (clamped into range). */
export function paginate<T>(items: readonly T[], page: number, pageSize: number): T[] {
  const safe = Math.min(Math.max(1, page), pageCount(items.length, pageSize));
  return items.slice((safe - 1) * pageSize, safe * pageSize);
}
