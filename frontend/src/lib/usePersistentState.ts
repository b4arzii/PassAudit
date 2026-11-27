import { useCallback, useState } from 'react';

import { readStorage, writeStorage } from './storage.ts';

/** A boolean UI preference remembered in localStorage (never anything sensitive). */
export function usePersistentBoolean(
  key: string,
  initial: boolean,
): [boolean, (value: boolean) => void] {
  const [value, setValue] = useState<boolean>(() => {
    const stored = readStorage(key);
    return stored === null ? initial : stored === 'true';
  });
  const update = useCallback(
    (next: boolean) => {
      setValue(next);
      writeStorage(key, String(next));
    },
    [key],
  );
  return [value, update];
}
