import { act, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef } from 'react';

import { cn } from './cn.ts';
import { getFocusable, useFocusTrap, useScrollLock } from './overlay.ts';
import { readStorage, writeStorage } from './storage.ts';
import { usePersistentBoolean } from './usePersistentState.ts';

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('cn', () => {
  it('joins truthy values and drops falsy ones', () => {
    expect(cn('a', false, null, undefined, '', 'b')).toBe('a b');
    expect(cn()).toBe('');
  });
});

describe('storage helpers', () => {
  it('round-trips values', () => {
    writeStorage('k', 'v');
    expect(readStorage('k')).toBe('v');
    expect(readStorage('missing')).toBeNull();
  });

  it('never throw, even when storage is blocked or full', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError');
    });
    expect(readStorage('k')).toBeNull();
    expect(() => {
      writeStorage('k', 'v');
    }).not.toThrow();
  });
});

describe('usePersistentBoolean', () => {
  it('uses the initial value, then remembers updates', () => {
    const { result, rerender } = renderHook(() => usePersistentBoolean('flag', true));
    expect(result.current[0]).toBe(true);
    act(() => {
      result.current[1](false);
    });
    expect(result.current[0]).toBe(false);
    expect(window.localStorage.getItem('flag')).toBe('false');
    rerender();
    const second = renderHook(() => usePersistentBoolean('flag', true));
    expect(second.result.current[0]).toBe(false); // read back from storage
  });

  it('treats unexpected stored values as false', () => {
    window.localStorage.setItem('flag', 'banana');
    expect(renderHook(() => usePersistentBoolean('flag', true)).result.current[0]).toBe(false);
  });
});

describe('useScrollLock', () => {
  it('is reference-counted: scrolling returns only when the last lock is released', () => {
    const a = renderHook(() => {
      useScrollLock(true);
    });
    const b = renderHook(() => {
      useScrollLock(true);
    });
    expect(document.body.style.overflow).toBe('hidden');
    a.unmount();
    expect(document.body.style.overflow).toBe('hidden');
    b.unmount();
    expect(document.body.style.overflow).toBe('');
  });

  it('does nothing while inactive', () => {
    renderHook(() => {
      useScrollLock(false);
    });
    expect(document.body.style.overflow).toBe('');
  });
});

describe('focus trap', () => {
  function Trap({ children, active = true }: { children?: React.ReactNode; active?: boolean }) {
    const ref = useRef<HTMLDivElement>(null);
    useFocusTrap(ref, active);
    return (
      <div ref={ref} tabIndex={-1} data-testid="trap">
        {children}
      </div>
    );
  }

  it('focuses the container when it has nothing focusable, and keeps focus there on Tab', async () => {
    const user = userEvent.setup();
    render(<Trap />);
    expect(screen.getByTestId('trap')).toHaveFocus();
    await user.tab();
    expect(screen.getByTestId('trap')).toHaveFocus();
  });

  it('wraps focus from the last control to the first and back', async () => {
    const user = userEvent.setup();
    render(
      <Trap>
        <button type="button">first</button>
        <button type="button">last</button>
      </Trap>,
    );
    expect(screen.getByRole('button', { name: 'first' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'last' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'first' })).toHaveFocus();
    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'last' })).toHaveFocus();
  });

  it('is inert when not active', () => {
    render(
      <>
        <button type="button">outside</button>
        <Trap active={false}>
          <button type="button">inside</button>
        </Trap>
      </>,
    );
    expect(screen.getByRole('button', { name: 'inside' })).not.toHaveFocus();
  });

  it('getFocusable skips disabled, hidden and inert elements', () => {
    const host = document.createElement('div');
    host.innerHTML = `
      <button>ok</button>
      <button disabled>disabled</button>
      <input type="hidden" />
      <a href="#x">link</a>
      <div tabindex="-1">not tabbable</div>
      <div tabindex="0">tabbable</div>
      <button aria-hidden="true">hidden</button>
      <button inert>inert</button>`;
    expect(getFocusable(host).map((el) => el.textContent.trim())).toEqual([
      'ok',
      'link',
      'tabbable',
    ]);
  });
});
