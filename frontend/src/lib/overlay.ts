import { useEffect } from 'react';
import type { RefObject } from 'react';

/** Elements a keyboard user can tab to. */
const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(',');

export function getFocusable(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.hasAttribute('inert') && el.getAttribute('aria-hidden') !== 'true',
  );
}

/**
 * Trap Tab / Shift+Tab inside `ref` while `active`, move focus in on open and restore it to
 * whatever had focus before on close.
 */
export function useFocusTrap(ref: RefObject<HTMLElement | null>, active: boolean): void {
  useEffect(() => {
    const container = ref.current;
    if (!active || !container) return;

    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const preferred = container.querySelector<HTMLElement>('[data-autofocus]');
    (preferred ?? getFocusable(container)[0] ?? container).focus({ preventScroll: true });

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key !== 'Tab' || !container) return;
      const items = getFocusable(container);
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) {
        event.preventDefault();
        container.focus();
        return;
      }
      const current = document.activeElement;
      if (event.shiftKey && (current === first || current === container)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && current === last) {
        event.preventDefault();
        first.focus();
      } else if (!container.contains(current)) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      // Restore focus in a microtask: by then every cleanup in this commit has run, including
      // the one that lifts `inert` from the page - browsers refuse to focus an inert element.
      queueMicrotask(() => {
        if (previouslyFocused?.isConnected) previouslyFocused.focus({ preventScroll: true });
      });
    };
  }, [ref, active]);
}

let scrollLocks = 0;
let savedOverflow = '';
let savedPadding = '';

/** Prevent the page behind a modal from scrolling (reference-counted for stacked modals). */
export function useScrollLock(active: boolean): void {
  useEffect(() => {
    if (!active) return;
    const body = document.body;
    if (scrollLocks === 0) {
      savedOverflow = body.style.overflow;
      savedPadding = body.style.paddingRight;
      const scrollbar = window.innerWidth - document.documentElement.clientWidth;
      body.style.overflow = 'hidden';
      if (scrollbar > 0) body.style.paddingRight = `${String(scrollbar)}px`; // avoid layout shift
    }
    scrollLocks += 1;
    return () => {
      scrollLocks -= 1;
      if (scrollLocks === 0) {
        body.style.overflow = savedOverflow;
        body.style.paddingRight = savedPadding;
      }
    };
  }, [active]);
}

/**
 * Make everything outside `ref` inert (not focusable, hidden from assistive technology)
 * while a modal is open. Complements `aria-modal`, which not every screen reader honours.
 */
export function useInertOutside(ref: RefObject<HTMLElement | null>, active: boolean): void {
  useEffect(() => {
    const modal = ref.current;
    if (!active || !modal) return;
    const changed: HTMLElement[] = [];
    for (const child of Array.from(document.body.children)) {
      if (
        child instanceof HTMLElement &&
        !child.contains(modal) &&
        !child.hasAttribute('inert') &&
        !child.hasAttribute('data-keep-active') // e.g. notifications must stay announceable
      ) {
        child.setAttribute('inert', '');
        changed.push(child);
      }
    }
    return () => {
      for (const el of changed) el.removeAttribute('inert');
    };
  }, [ref, active]);
}

/** Call `onEscape` when Escape is pressed while `active`. */
export function useEscapeKey(active: boolean, onEscape: () => void): void {
  useEffect(() => {
    if (!active) return;
    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape' && !event.defaultPrevented) {
        event.stopPropagation();
        onEscape();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [active, onEscape]);
}
