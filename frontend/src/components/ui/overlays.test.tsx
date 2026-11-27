import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';

import { expectNoA11yViolations } from '../../test/a11y.ts';
import { Button, ConfirmDialog, Dialog, Input, ToastProvider, useToast } from './index.ts';

function DialogHarness({ dismissible = true }: { dismissible?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div id="app">
      <button
        type="button"
        onClick={() => {
          setOpen(true);
        }}
      >
        Open
      </button>
      <button type="button">Other page control</button>
      <Dialog
        open={open}
        onClose={() => {
          setOpen(false);
        }}
        title="Rename"
        description="Pick a new name."
        dismissible={dismissible}
        footer={
          <>
            <Button
              variant="outline"
              onClick={() => {
                setOpen(false);
              }}
            >
              Cancel
            </Button>
            <Button>Save</Button>
          </>
        }
      >
        <Input aria-label="Name" />
      </Dialog>
    </div>
  );
}

describe('Dialog', () => {
  it('renders nothing while closed', () => {
    render(<DialogHarness />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('is a modal dialog named by its title and described by its description', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    const dialog = screen.getByRole('dialog', { name: 'Rename' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAccessibleDescription('Pick a new name.');
  });

  it('moves focus into the dialog and returns it to the opener on close', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);
    const opener = screen.getByRole('button', { name: 'Open' });
    await user.click(opener);
    expect(screen.getByRole('dialog')).toContainElement(document.activeElement as HTMLElement);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await act(async () => {
      await Promise.resolve(); // focus is restored in a microtask, after `inert` is lifted
    });
    expect(opener).toHaveFocus();
  });

  it('traps Tab and Shift+Tab inside the dialog', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    const dialog = screen.getByRole('dialog');
    for (let i = 0; i < 8; i++) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
    for (let i = 0; i < 8; i++) {
      await user.tab({ shift: true });
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }
  });

  it('closes with Escape, the close button and a backdrop press', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    await user.click(screen.getByRole('button', { name: 'Open' }));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Open' }));
    await user.click(screen.getByRole('button', { name: 'Close dialog' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Open' }));
    const backdrop = screen.getByRole('dialog').previousElementSibling as HTMLElement;
    await user.pointer({ keys: '[MouseLeft]', target: backdrop });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('a non-dismissible dialog ignores Escape and backdrop, and has no close button', async () => {
    const user = userEvent.setup();
    render(<DialogHarness dismissible={false} />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await user.pointer({
      keys: '[MouseLeft]',
      target: screen.getByRole('dialog').previousElementSibling as HTMLElement,
    });
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Close dialog' })).not.toBeInTheDocument();
  });

  it('locks page scroll and makes the rest of the page inert, then restores both', async () => {
    const user = userEvent.setup();
    const { container } = render(<DialogHarness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    expect(document.body.style.overflow).toBe('hidden');
    expect(container).toHaveAttribute('inert');
    await user.keyboard('{Escape}');
    expect(document.body.style.overflow).toBe('');
    expect(container).not.toHaveAttribute('inert');
  });

  it('autofocuses the element marked data-autofocus', async () => {
    const user = userEvent.setup();
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button
            type="button"
            onClick={() => {
              setOpen(true);
            }}
          >
            Open
          </button>
          <Dialog
            open={open}
            onClose={() => {
              setOpen(false);
            }}
            title="T"
          >
            <Input aria-label="First" />
            <Input aria-label="Second" data-autofocus />
          </Dialog>
        </>
      );
    }
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    expect(screen.getByLabelText('Second')).toHaveFocus();
  });

  it('has no accessibility violations when open', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);
    await user.click(screen.getByRole('button', { name: 'Open' }));
    await expectNoA11yViolations(screen.getByRole('dialog'));
  });
});

describe('ConfirmDialog', () => {
  it('starts focus on Cancel, so a stray Enter cannot confirm', async () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        open
        onClose={onClose}
        onConfirm={onConfirm}
        title="Delete?"
        confirmLabel="Delete"
        tone="danger"
      />,
    );
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await userEvent.setup().keyboard('{Enter}');
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('confirm calls onConfirm; loading disables further confirms', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const { rerender } = render(
      <ConfirmDialog open onClose={() => undefined} onConfirm={onConfirm} title="Sure?" />,
    );
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    rerender(
      <ConfirmDialog open onClose={() => undefined} onConfirm={onConfirm} title="Sure?" loading />,
    );
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

// ------------------------------------------------------------------------- toasts

function ToastHarness({ onReady }: { onReady?: (api: ReturnType<typeof useToast>) => void }) {
  const api = useToast();
  onReady?.(api);
  return (
    <div>
      <button
        type="button"
        onClick={() => {
          api.success('Saved', 'Settings updated.');
        }}
      >
        Success
      </button>
      <button
        type="button"
        onClick={() => {
          api.error('Failed', 'Try again.');
        }}
      >
        Error
      </button>
    </div>
  );
}

/** Queries scoped to the visible stack (the hidden announcer deliberately repeats the text). */
function stack() {
  return within(screen.getByRole('region', { name: 'Notifications' }));
}

function renderToasts() {
  let api!: ReturnType<typeof useToast>;
  render(
    <ToastProvider>
      <ToastHarness
        onReady={(a) => {
          api = a;
        }}
      />
    </ToastProvider>,
  );
  return () => api;
}

describe('Toasts', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('useToast outside a provider fails loudly', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => render(<ToastHarness />)).toThrow(/ToastProvider/);
    spy.mockRestore();
  });

  it('shows a toast in a labelled notifications region', async () => {
    const user = userEvent.setup();
    renderToasts();
    await user.click(screen.getByRole('button', { name: 'Success' }));
    const region = screen.getByRole('region', { name: 'Notifications' });
    expect(region).toHaveTextContent('Saved');
    expect(region).toHaveTextContent('Settings updated.');
  });

  it('announces politely for normal toasts and assertively for errors', async () => {
    const user = userEvent.setup();
    renderToasts();
    await user.click(screen.getByRole('button', { name: 'Success' }));
    expect(screen.getByRole('status')).toHaveTextContent('Saved. Settings updated.');
    await user.click(screen.getByRole('button', { name: 'Error' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Failed. Try again.');
  });

  it('re-announces an identical message shown twice', () => {
    vi.useFakeTimers();
    const get = renderToasts();
    act(() => {
      get().info('Same');
    });
    const first = screen.getByRole('status').firstElementChild;
    act(() => {
      get().info('Same');
    });
    const second = screen.getByRole('status').firstElementChild;
    expect(second).not.toBe(first); // a fresh node is what makes assistive tech speak again
  });

  it('never steals focus', async () => {
    const user = userEvent.setup();
    renderToasts();
    const trigger = screen.getByRole('button', { name: 'Success' });
    await user.click(trigger);
    expect(trigger).toHaveFocus();
  });

  it('auto-dismisses after its duration', () => {
    vi.useFakeTimers();
    const get = renderToasts();
    act(() => {
      get().show({ title: 'Brief', duration: 3000 });
    });
    expect(stack().getByText('Brief')).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(2999);
    });
    expect(stack().getByText('Brief')).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(2);
    });
    expect(stack().queryByText('Brief')).not.toBeInTheDocument();
  });

  it('errors stay longer than other toasts by default', () => {
    vi.useFakeTimers();
    const get = renderToasts();
    act(() => {
      get().error('Oops');
      get().info('Hi');
    });
    act(() => {
      vi.advanceTimersByTime(6100);
    });
    expect(screen.getByRole('region', { name: 'Notifications' })).not.toHaveTextContent('Hi');
    expect(screen.getByRole('region', { name: 'Notifications' })).toHaveTextContent('Oops');
    act(() => {
      vi.advanceTimersByTime(4000);
    });
    expect(screen.getByRole('region', { name: 'Notifications' })).not.toHaveTextContent('Oops');
  });

  it('pauses while hovered and resumes after', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const get = renderToasts();
    act(() => {
      get().show({ title: 'Hover me', duration: 2000 });
    });
    const item = stack().getByText('Hover me').closest('li') as HTMLElement;
    await user.hover(item);
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(stack().getByText('Hover me')).toBeInTheDocument();
    await user.unhover(item);
    act(() => {
      vi.advanceTimersByTime(2100);
    });
    expect(stack().queryByText('Hover me')).not.toBeInTheDocument();
  });

  it('a persistent toast (duration null) never auto-dismisses', () => {
    vi.useFakeTimers();
    const get = renderToasts();
    act(() => {
      get().show({ title: 'Stays', duration: null });
    });
    act(() => {
      vi.advanceTimersByTime(600_000);
    });
    expect(stack().getByText('Stays')).toBeInTheDocument();
  });

  it('dismisses with the button and with Escape', async () => {
    const user = userEvent.setup();
    const get = renderToasts();
    act(() => {
      get().show({ title: 'One', duration: null });
      get().show({ title: 'Two', duration: null });
    });
    const dismiss = screen.getAllByRole('button', { name: 'Dismiss notification' });
    const firstDismiss = dismiss[0];
    if (!firstDismiss) throw new Error('expected a dismiss button');
    await user.click(firstDismiss);
    expect(stack().queryByText('One')).not.toBeInTheDocument();
    screen.getByRole('button', { name: 'Dismiss notification' }).focus();
    await user.keyboard('{Escape}');
    expect(stack().queryByText('Two')).not.toBeInTheDocument();
  });

  it('shows at most four toasts, dropping the oldest', () => {
    const get = renderToasts();
    act(() => {
      for (let i = 1; i <= 6; i++) get().show({ title: `Toast ${String(i)}`, duration: null });
    });
    const region = screen.getByRole('region', { name: 'Notifications' });
    expect(region.querySelectorAll('li')).toHaveLength(4);
    expect(region).not.toHaveTextContent('Toast 1');
    expect(region).toHaveTextContent('Toast 6');
  });

  it('an action button runs its handler and dismisses the toast', async () => {
    const user = userEvent.setup();
    const onUndo = vi.fn();
    const get = renderToasts();
    act(() => {
      get().show({ title: 'Archived', duration: null, action: { label: 'Undo', onClick: onUndo } });
    });
    await user.click(screen.getByRole('button', { name: 'Undo' }));
    expect(onUndo).toHaveBeenCalledTimes(1);
    expect(stack().queryByText('Archived')).not.toBeInTheDocument();
  });

  it('dismiss(id) and dismissAll remove toasts', () => {
    const get = renderToasts();
    let id = '';
    act(() => {
      id = get().show({ title: 'A', duration: null });
      get().show({ title: 'B', duration: null });
    });
    act(() => {
      get().dismiss(id);
    });
    expect(stack().queryByText('A')).not.toBeInTheDocument();
    expect(stack().getByText('B')).toBeInTheDocument();
    act(() => {
      get().dismissAll();
    });
    expect(stack().queryByText('B')).not.toBeInTheDocument();
  });

  it('stays announceable while a dialog has made the page inert', async () => {
    const user = userEvent.setup();
    function Harness() {
      const toast = useToast();
      return (
        <Dialog open onClose={() => undefined} title="Modal">
          <Button
            onClick={() => {
              toast.error('Inside dialog');
            }}
          >
            Fire
          </Button>
        </Dialog>
      );
    }
    const { container } = render(
      <ToastProvider>
        <Harness />
      </ToastProvider>,
    );
    expect(container).toHaveAttribute('inert');
    await user.click(screen.getByRole('button', { name: 'Fire' }));
    const region = screen.getByRole('region', { name: 'Notifications' });
    expect(region.closest('[inert]')).toBeNull();
    expect(screen.getByRole('alert')).toHaveTextContent('Inside dialog');
  });

  it('has no accessibility violations with toasts showing', async () => {
    const get = renderToasts();
    act(() => {
      get().show({
        title: 'Hello',
        description: 'World',
        duration: null,
        action: { label: 'Do', onClick: () => undefined },
      });
    });
    await expectNoA11yViolations(document.body);
  });
});
