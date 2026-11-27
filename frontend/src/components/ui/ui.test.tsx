import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';

import { expectNoA11yViolations } from '../../test/a11y.ts';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardDescription,
  CardTitle,
  Checkbox,
  EmptyState,
  Field,
  IconButton,
  Input,
  PageHeader,
  PasswordInput,
  Progress,
  SegmentedControl,
  Select,
  Skeleton,
  Spinner,
  Switch,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  TableEmpty,
  Textarea,
  buttonClasses,
} from './index.ts';

describe('Button', () => {
  it('renders a type="button" by default (never submits a form by accident)', () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole('button', { name: 'Save' })).toHaveAttribute('type', 'button');
  });

  it('calls onClick, and respects disabled', async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    const { rerender } = render(<Button onClick={onClick}>Go</Button>);
    await user.click(screen.getByRole('button', { name: 'Go' }));
    expect(onClick).toHaveBeenCalledTimes(1);

    rerender(
      <Button onClick={onClick} disabled>
        Go
      </Button>,
    );
    await user.click(screen.getByRole('button', { name: 'Go' }));
    expect(onClick).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Go' })).toBeDisabled();
  });

  it('loading: announces busy, ignores clicks, but stays focusable', async () => {
    const user = userEvent.setup();
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Analysing
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Analysing' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(button).toHaveAttribute('aria-disabled', 'true');
    expect(button).not.toBeDisabled();
    await user.tab();
    expect(button).toHaveFocus();
    await user.click(button);
    await user.keyboard('{Enter}');
    expect(onClick).not.toHaveBeenCalled();
  });

  it('is not busy when not loading', () => {
    render(<Button>Idle</Button>);
    expect(screen.getByRole('button')).not.toHaveAttribute('aria-busy');
  });

  it.each(['primary', 'secondary', 'outline', 'ghost', 'danger'] as const)(
    'variant %s renders distinct styling',
    (variant) => {
      render(<Button variant={variant}>x</Button>);
      expect(screen.getByRole('button').className).toContain(
        buttonClasses({ variant }).split(' ')[0],
      );
    },
  );

  it('buttonClasses styles links like buttons', () => {
    render(
      <a href="/x" className={buttonClasses({ variant: 'outline', size: 'lg', fullWidth: true })}>
        Link
      </a>,
    );
    const link = screen.getByRole('link', { name: 'Link' });
    expect(link.className).toContain('h-12');
    expect(link.className).toContain('w-full');
  });

  it('forwards refs and extra attributes', () => {
    const ref = { current: null as HTMLButtonElement | null };
    render(
      <Button ref={ref} data-testid="b" aria-describedby="hint">
        x
      </Button>,
    );
    expect(ref.current).toBe(screen.getByTestId('b'));
    expect(ref.current).toHaveAttribute('aria-describedby', 'hint');
  });
});

describe('IconButton', () => {
  it('is named by its label (and titled for sighted users)', () => {
    render(
      <IconButton label="Delete item">
        <svg aria-hidden="true" />
      </IconButton>,
    );
    const button = screen.getByRole('button', { name: 'Delete item' });
    expect(button).toHaveAttribute('title', 'Delete item');
  });

  it('loading ignores clicks', async () => {
    const onClick = vi.fn();
    render(
      <IconButton label="Save" loading onClick={onClick}>
        <svg aria-hidden="true" />
      </IconButton>,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Save' }));
    expect(onClick).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Save' })).toHaveAttribute('aria-busy', 'true');
  });
});

describe('Badge', () => {
  it('keeps meaning in text; the dot is decorative', () => {
    const { container } = render(
      <Badge tone="danger" dot>
        Critical risk
      </Badge>,
    );
    expect(screen.getByText('Critical risk')).toBeInTheDocument();
    expect(container.querySelector('[aria-hidden="true"]')).toBeInTheDocument();
  });

  it('supports an outline style and sizes', () => {
    render(
      <Badge outline size="sm">
        Planned
      </Badge>,
    );
    expect(screen.getByText('Planned').className).toContain('border');
  });
});

describe('Field + controls', () => {
  it('associates the label with the control', () => {
    render(
      <Field label="Display name">
        <Input />
      </Field>,
    );
    expect(screen.getByLabelText('Display name')).toBeInTheDocument();
  });

  it('describes the control with the hint and the error, and marks it invalid', () => {
    render(
      <Field label="E-mail" hint="We never send mail." error="Enter a valid address.">
        <Input />
      </Field>,
    );
    const input = screen.getByLabelText('E-mail');
    expect(input).toBeInvalid();
    expect(input).toHaveAccessibleDescription('We never send mail. Enter a valid address.');
  });

  it('is valid with no error, and does not mention missing hints', () => {
    render(
      <Field label="Name">
        <Input />
      </Field>,
    );
    const input = screen.getByLabelText('Name');
    expect(input).toBeValid();
    expect(input).not.toHaveAttribute('aria-describedby');
  });

  it('required adds the native attribute and a decorative asterisk', () => {
    render(
      <Field label="Name" required>
        <Input />
      </Field>,
    );
    expect(screen.getByLabelText(/Name/)).toBeRequired();
  });

  it('disabled propagates to the control', () => {
    render(
      <Field label="Locked" disabled>
        <Input />
      </Field>,
    );
    expect(screen.getByLabelText('Locked')).toBeDisabled();
  });

  it('hideLabel keeps the label for assistive technology', () => {
    render(
      <Field label="Search" hideLabel>
        <Input />
      </Field>,
    );
    expect(screen.getByLabelText('Search')).toBeInTheDocument();
    expect(screen.getByText('Search').className).toContain('sr-only');
  });

  it('works for Textarea and Select too', () => {
    render(
      <>
        <Field label="Notes" error="Too short">
          <Textarea />
        </Field>
        <Field label="Usage" hint="Pick one">
          <Select defaultValue="b">
            <option value="a">A</option>
            <option value="b">B</option>
          </Select>
        </Field>
      </>,
    );
    expect(screen.getByLabelText('Notes')).toBeInvalid();
    expect(screen.getByLabelText('Usage')).toHaveAccessibleDescription('Pick one');
    expect(screen.getByLabelText('Usage')).toHaveValue('b');
  });

  it('a standalone Input honours its own aria-invalid', () => {
    render(<Input aria-label="x" aria-invalid="true" />);
    expect(screen.getByLabelText('x')).toBeInvalid();
  });
});

describe('PasswordInput', () => {
  it('is hidden by default with privacy-safe attributes', () => {
    render(
      <Field label="Password">
        <PasswordInput />
      </Field>,
    );
    const input = screen.getByLabelText('Password');
    expect(input).toHaveAttribute('type', 'password');
    expect(input).toHaveAttribute('autocomplete', 'off');
    expect(input).toHaveAttribute('autocapitalize', 'off');
    expect(input).toHaveAttribute('spellcheck', 'false');
  });

  it('the reveal toggle exposes its state and reveals/hides the value', async () => {
    const user = userEvent.setup();
    render(
      <Field label="Password">
        <PasswordInput />
      </Field>,
    );
    const toggle = screen.getByRole('button', { name: 'Show password' });
    expect(toggle).toHaveAttribute('aria-pressed', 'false');
    await user.click(toggle);
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'text');
    await user.click(toggle);
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
  });

  it('the toggle never submits a form', async () => {
    const onSubmit = vi.fn((e: React.SyntheticEvent) => {
      e.preventDefault();
    });
    render(
      <form onSubmit={onSubmit}>
        <Field label="Password">
          <PasswordInput />
        </Field>
      </form>,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Show password' }));
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('can omit the toggle and cannot be switched to a visible type by props', () => {
    render(<PasswordInput revealable={false} aria-label="Secret" />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Secret')).toHaveAttribute('type', 'password');
  });

  it('is a controlled-friendly input (the parent owns the value)', async () => {
    const user = userEvent.setup();
    function Parent() {
      const [value, setValue] = useState('');
      return (
        <>
          <PasswordInput
            aria-label="Secret"
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
            }}
          />
          <output>{value.length}</output>
        </>
      );
    }
    render(<Parent />);
    await user.type(screen.getByLabelText('Secret'), 'abc123');
    expect(screen.getByRole('status')).toHaveTextContent('6');
  });
});

describe('Checkbox, Switch, SegmentedControl', () => {
  it('Checkbox toggles with click and Space, and is described', async () => {
    const user = userEvent.setup();
    render(<Checkbox label="Include advice" description="Adds tips" />);
    const box = screen.getByRole('checkbox', { name: 'Include advice' });
    expect(box).toHaveAccessibleDescription('Adds tips');
    await user.click(box);
    expect(box).toBeChecked();
    box.focus();
    await user.keyboard(' ');
    expect(box).not.toBeChecked();
  });

  it('Switch is role=switch, toggles with Space and click on its label', async () => {
    const user = userEvent.setup();
    render(<Switch label="Notifications" />);
    const toggle = screen.getByRole('switch', { name: 'Notifications' });
    expect(toggle).not.toBeChecked();
    await user.click(screen.getByText('Notifications'));
    expect(toggle).toBeChecked();
    toggle.focus();
    await user.keyboard(' ');
    expect(toggle).not.toBeChecked();
  });

  it('SegmentedControl is a labelled radio group with arrow-key navigation', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SegmentedControl
        legend="Theme"
        value="light"
        onChange={onChange}
        options={[
          { value: 'light', label: 'Light' },
          { value: 'dark', label: 'Dark' },
        ]}
      />,
    );
    const group = screen.getByRole('group', { name: 'Theme' });
    expect(within(group).getAllByRole('radio')).toHaveLength(2);
    expect(screen.getByRole('radio', { name: 'Light' })).toBeChecked();
    screen.getByRole('radio', { name: 'Light' }).focus();
    await user.keyboard('{ArrowRight}');
    expect(onChange).toHaveBeenCalledWith('dark');
  });
});

describe('Table', () => {
  function Demo({ sort }: { sort: 'ascending' | 'descending' | 'none' }) {
    return (
      <Table label="Policies" caption="Example policies">
        <THead>
          <TR>
            <TH sort={sort} onSort={() => undefined}>
              Name
            </TH>
            <TH align="right">Rules</TH>
          </TR>
        </THead>
        <TBody>
          <TR>
            <TD>Default</TD>
            <TD align="right">4</TD>
          </TR>
        </TBody>
      </Table>
    );
  }

  it('has real table semantics, a caption, and a named focusable scroll region', () => {
    render(<Demo sort="ascending" />);
    expect(screen.getByRole('table', { name: 'Example policies' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Policies' })).toHaveAttribute('tabindex', '0');
    expect(screen.getAllByRole('columnheader')).toHaveLength(2);
    expect(screen.getByRole('cell', { name: 'Default' })).toBeInTheDocument();
  });

  it.each(['ascending', 'descending', 'none'] as const)(
    'sets aria-sort=%s on sortable headers',
    (sort) => {
      render(<Demo sort={sort} />);
      expect(screen.getByRole('columnheader', { name: 'Name' })).toHaveAttribute('aria-sort', sort);
      expect(screen.getByRole('columnheader', { name: 'Rules' })).not.toHaveAttribute('aria-sort');
    },
  );

  it('the sort control is a real button that fires onSort', async () => {
    const onSort = vi.fn();
    render(
      <Table label="t">
        <THead>
          <TR>
            <TH sort="none" onSort={onSort}>
              Name
            </TH>
          </TR>
        </THead>
      </Table>,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Name' }));
    expect(onSort).toHaveBeenCalledTimes(1);
  });

  it('TableEmpty spans all columns', () => {
    render(
      <Table label="t">
        <TBody>
          <TableEmpty colSpan={3}>Nothing here</TableEmpty>
        </TBody>
      </Table>,
    );
    expect(screen.getByRole('cell', { name: 'Nothing here' })).toHaveAttribute('colspan', '3');
  });
});

describe('Alert', () => {
  it('errors use role=alert, everything else role=status', () => {
    const { rerender } = render(<Alert tone="danger" title="Failed" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Failed');
    rerender(<Alert tone="info" title="FYI" />);
    expect(screen.getByRole('status')).toHaveTextContent('FYI');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('can be dismissed with a labelled button', async () => {
    const onDismiss = vi.fn();
    render(
      <Alert title="x" onDismiss={onDismiss}>
        body
      </Alert>,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(onDismiss).toHaveBeenCalled();
  });
});

describe('Loading components', () => {
  it('Spinner announces its label; decorative spinners stay silent', () => {
    const { rerender } = render(<Spinner label="Analysing" />);
    expect(screen.getByRole('status')).toHaveTextContent('Analysing');
    rerender(<Spinner label={null} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('Skeleton is hidden from assistive technology', () => {
    const { container } = render(<Skeleton />);
    expect(container.firstElementChild).toHaveAttribute('aria-hidden', 'true');
  });

  it('Progress exposes value, bounds and a name; clamps out-of-range values', () => {
    const { rerender } = render(<Progress label="Analysing" value={40} />);
    const bar = screen.getByRole('progressbar', { name: 'Analysing' });
    expect(bar).toHaveAttribute('aria-valuenow', '40');
    expect(bar).toHaveAttribute('aria-valuemin', '0');
    expect(bar).toHaveAttribute('aria-valuemax', '100');
    rerender(<Progress label="Analysing" value={150} />);
    expect(bar).toHaveAttribute('aria-valuenow', '100');
    rerender(<Progress label="Analysing" value={-5} />);
    expect(bar).toHaveAttribute('aria-valuenow', '0');
  });

  it('an indeterminate Progress has no aria-valuenow', () => {
    render(<Progress label="Preparing" />);
    expect(screen.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
  });
});

describe('Card, PageHeader, EmptyState', () => {
  it('Card renders as the requested element, with a chosen heading level', () => {
    render(
      <Card as="article" aria-label="Summary">
        <CardTitle level={2}>Title</CardTitle>
        <CardDescription>Desc</CardDescription>
      </Card>,
    );
    expect(screen.getByRole('article', { name: 'Summary' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'Title' })).toBeInTheDocument();
  });

  it('PageHeader renders the page h1, eyebrow, description and actions', () => {
    render(
      <PageHeader
        title="Audit"
        eyebrow="Workspace"
        description="Analyse."
        actions={<button type="button">Go</button>}
      />,
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Audit' })).toBeInTheDocument();
    expect(screen.getByText('Workspace')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Go' })).toBeInTheDocument();
  });

  it('EmptyState has a heading, text and an action; its icon is decorative', () => {
    const { container } = render(
      <EmptyState
        icon={<svg />}
        title="Nothing yet"
        description="Add one."
        action={<button type="button">Add</button>}
      />,
    );
    expect(screen.getByRole('heading', { name: 'Nothing yet' })).toBeInTheDocument();
    expect(container.querySelector('[aria-hidden="true"]')).toBeInTheDocument();
  });
});

describe('accessibility (axe)', () => {
  it('a kitchen-sink of components has no violations', async () => {
    const { container } = render(
      <main>
        <PageHeader title="Kitchen sink" />
        <Button>Primary</Button>
        <Button loading>Busy</Button>
        <IconButton label="Close">
          <svg aria-hidden="true" />
        </IconButton>
        <Badge tone="success" dot>
          Passed
        </Badge>
        <Field label="Name" hint="Hint" required>
          <Input />
        </Field>
        <Field label="Password">
          <PasswordInput />
        </Field>
        <Field label="Bad" error="Wrong">
          <Input />
        </Field>
        <Field label="Notes">
          <Textarea />
        </Field>
        <Field label="Usage">
          <Select>
            <option>One</option>
          </Select>
        </Field>
        <Checkbox label="Check" />
        <Switch label="Switch" />
        <SegmentedControl
          legend="Mode"
          value="a"
          onChange={() => undefined}
          options={[
            { value: 'a', label: 'A' },
            { value: 'b', label: 'B' },
          ]}
        />
        <Alert tone="warning" title="Careful" />
        <Progress label="Working" value={30} />
        <Table label="Data" caption="Data">
          <THead>
            <TR>
              <TH sort="ascending" onSort={() => undefined}>
                Col
              </TH>
            </TR>
          </THead>
          <TBody>
            <TR>
              <TD>Cell</TD>
            </TR>
          </TBody>
        </Table>
        <EmptyState title="Empty" />
      </main>,
    );
    await expectNoA11yViolations(container, { page: true });
  });
});
