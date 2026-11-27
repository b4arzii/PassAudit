import { useEffect, useRef, useState } from 'react';
import type { RefObject } from 'react';
import { useLocation } from 'react-router-dom';

import { APP_NAME, pageTitle } from './navigation.ts';

/**
 * Single-page apps do not reload on navigation, so assistive technology is told what
 * happened: the document title is updated, the new page is announced through a polite live
 * region, and focus moves to <main> (but not on the very first load, which would skip the
 * skip-link and the header).
 */
export function RouteAnnouncer({ mainRef }: { mainRef: RefObject<HTMLElement | null> }) {
  const { pathname } = useLocation();
  const [message, setMessage] = useState('');
  const first = useRef(true);

  useEffect(() => {
    const title = pageTitle(pathname);
    document.title =
      pathname === '/' ? `${APP_NAME} - Local password auditing` : `${title} - ${APP_NAME}`;
    if (first.current) {
      first.current = false;
      return;
    }
    setMessage(`Navigated to ${title}`);
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, [pathname, mainRef]);

  return (
    <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
      {message}
    </div>
  );
}
