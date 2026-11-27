import { ShieldQuestion } from 'lucide-react';

import type { BreachMode, ExposureOptions } from '../../api/types.ts';
import { useApiStatus } from '../../state/api.ts';
import { Alert, Checkbox, Field, Select } from '../ui/index.ts';

export interface ExposureFieldsProps {
  value: ExposureOptions;
  onChange: (next: ExposureOptions) => void;
  disabled?: boolean;
  /** Batch audits show the same options; the wording of the intro differs a little. */
  subject?: string;
}

/**
 * The opt-in external checks. Everything starts **off**, nothing here is remembered, and an
 * option the server cannot do is shown but disabled (with the reason) instead of hidden.
 * Hidden entirely only when the backend predates the feature (no capabilities known).
 */
export function ExposureFields({
  value,
  onChange,
  disabled = false,
  subject = 'password',
}: ExposureFieldsProps) {
  const { capabilities } = useApiStatus();
  if (!capabilities) return null;
  const { breach, reuse_index: reuse } = capabilities;
  const host = breach.online_host ?? 'the breach service';

  return (
    <fieldset className="min-w-0 space-y-4 rounded-xl border border-line/10 bg-surface-2/40 p-4">
      <legend className="flex items-center gap-2 px-1 text-sm font-semibold text-fg">
        <ShieldQuestion aria-hidden="true" className="size-4 text-secondary" />
        Optional external checks
      </legend>
      <Field
        label="Check against known breaches"
        hint={`Off by default. Nothing about the ${subject} is looked up unless you choose a source.`}
        disabled={disabled}
      >
        <Select
          value={value.breach}
          onChange={(event) => {
            onChange({ ...value, breach: event.target.value as BreachMode });
          }}
        >
          <option value="off">Off (nothing is looked up)</option>
          <option value="local" disabled={!breach.local}>
            Local dataset (no network){breach.local ? '' : ' - not configured on this server'}
          </option>
          <option value="online" disabled={!breach.online}>
            Online, k-anonymity (sends a 5-character hash prefix)
            {breach.online ? '' : ' - not enabled on this server'}
          </option>
        </Select>
      </Field>

      {value.breach === 'online' && (
        <Alert tone="info" title="What leaves this machine">
          <p>
            Only the <strong>first 5 characters of the {subject}&apos;s SHA-1 hash</strong> are
            sent, to <span className="font-mono">{host}</span>. The {subject}, its full hash and the
            result never leave this machine; matching happens locally.
          </p>
          <p className="mt-2">
            The service can see that a check happened, when, from which address, and the 5-character
            prefix (shared by roughly a thousand known breached passwords). See the security notes
            for what that does and does not reveal.
          </p>
        </Alert>
      )}
      {value.breach === 'local' && (
        <p className="text-xs text-fg-muted">
          Searched in a hash file on the server. No network connection is made.
        </p>
      )}
      {!breach.local && !breach.online && (
        <p className="text-xs text-fg-muted">
          Breach checks are not enabled on this server. The operator can enable them (see the
          security documentation); nothing is sent anywhere meanwhile.
        </p>
      )}

      {reuse.available && (
        <Checkbox
          label="Check for reuse in the authorised datasets"
          description={`Compares against the server's local reuse index (${reuse.datasets.join(', ')}). Only dataset names are reported.${
            reuse.authorization_reference ? ` Authorisation: ${reuse.authorization_reference}.` : ''
          }`}
          checked={value.reuse}
          disabled={disabled}
          onChange={(event) => {
            onChange({ ...value, reuse: event.target.checked });
          }}
        />
      )}
    </fieldset>
  );
}
