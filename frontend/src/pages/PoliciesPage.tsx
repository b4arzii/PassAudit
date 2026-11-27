import { Download, RotateCcw, ScrollText } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { SyntheticEvent } from 'react';

import type { PolicyValidationResponse } from '../api/types.ts';
import { DemoBanner } from '../components/feature/DemoBanner.tsx';
import { ErrorPanel } from '../components/feature/ErrorPanel.tsx';
import { ConnectionNotice } from '../components/feature/Notices.tsx';
import { PolicyEditor } from '../components/feature/PolicyEditor.tsx';
import { PolicyResult } from '../components/feature/PolicyResult.tsx';
import {
  Alert,
  Badge,
  Button,
  Card,
  CardDescription,
  CardTitle,
  Disclosure,
  Field,
  FileDrop,
  PageHeader,
  PasswordInput,
  SkeletonText,
  Spinner,
  Textarea,
  useToast,
} from '../components/ui/index.ts';
import { demo } from '../demo/demo.ts';
import { friendlyError } from '../lib/errors.ts';
import { downloadText } from '../lib/export.ts';
import { POLICY_PRESETS, parsePolicyJson } from '../lib/policy.ts';
import type { DataSource } from '../lib/records.ts';
import { useAsyncAction } from '../lib/useAsyncAction.ts';
import { parsePersonalInfo, validatePasswordInput } from '../lib/validation.ts';
import { useApi, useApiStatus } from '../state/api.ts';
import { usePolicy } from '../state/policyState.ts';
import { usePreferences } from '../state/preferences.ts';
import type { PasswordPolicy } from '../api/types.ts';

interface CheckView {
  source: DataSource;
  result: PolicyValidationResponse;
  policy: PasswordPolicy | Record<string, unknown>;
}

/**
 * Define the policy used everywhere, and check a password against it rule by rule.
 *
 * The policy (rules only) is remembered in this browser. The password and personal details are
 * not: they stay in this component's state, go to the service in one POST body, and are cleared
 * after a successful check unless the user opted to keep them.
 */
export default function PoliciesPage() {
  const client = useApi();
  const { limits, capabilities } = useApiStatus();
  const { policy, setPolicy, reset, customised } = usePolicy();
  const { keepPassword } = usePreferences();
  const toast = useToast();

  const [editorKey, setEditorKey] = useState(0);
  const [importError, setImportError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [personalText, setPersonalText] = useState('');
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [personalError, setPersonalError] = useState<string | null>(null);
  const [view, setView] = useState<CheckView | null>(null);
  const action = useAsyncAction<PolicyValidationResponse>();

  const passwordRef = useRef<HTMLInputElement>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const loading = action.state.status === 'loading';

  useEffect(() => {
    if (view) resultHeading.current?.focus();
  }, [view]);

  function load(next: PasswordPolicy, message: string): void {
    setPolicy(next);
    setEditorKey((k) => k + 1); // remount the editor so its text boxes show the new values
    setImportError(null);
    toast.success('Policy updated', message);
  }

  async function applyProfile(name: string, title: string): Promise<void> {
    try {
      const profile = await client.policyProfile(name);
      load(profile.policy, `${title} is now active.`);
    } catch (error) {
      toast.error('Could not load the profile', friendlyError(error).message);
    }
  }

  async function onFile(file: File): Promise<void> {
    if (file.size > 64 * 1024) {
      setImportError('That file is too large to be a policy.');
      return;
    }
    try {
      const parsed = parsePolicyJson(await file.text());
      if (parsed.ok) load(parsed.policy, 'The policy file was loaded.');
      else setImportError(parsed.error);
    } catch {
      setImportError('That file could not be read.');
    }
  }

  async function submit(event?: SyntheticEvent): Promise<void> {
    event?.preventDefault();
    if (loading) return;
    const problem = validatePasswordInput(password, limits);
    const personal = parsePersonalInfo(personalText, limits);
    setPasswordError(problem);
    setPersonalError(personal.error);
    if (problem) {
      passwordRef.current?.focus();
      return;
    }
    if (personal.error) return;

    const applied = policy;
    const result = await action.run((signal) =>
      client.validatePolicy(
        { password, policy: applied, context: { personal_info: personal.items } },
        signal,
      ),
    );
    if (!result) return;
    setView({ source: 'live', result, policy: applied });
    if (!keepPassword) setPassword('');
  }

  function showDemo(): void {
    action.cancel();
    setView({
      source: 'demo',
      result: demo.policyCheck.result,
      policy: { ...demo.policyCheck.policy },
    });
  }

  const loadingResult = loading;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Workspace"
        title="Policies"
        description="Define a password policy and see exactly which rules a password breaks."
      />
      <ConnectionNotice />

      <Card as="section" aria-labelledby="policy-editor-h">
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle id="policy-editor-h" level={2}>
              Policy rules
            </CardTitle>
            <CardDescription>
              This policy is used by the Audit, Batch and check below.{' '}
              {customised ? 'It differs from the default.' : 'It is the default policy.'}
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              leadingIcon={<Download aria-hidden="true" className="size-4" />}
              onClick={() => {
                downloadText(
                  JSON.stringify(policy, null, 2) + '\n',
                  'passaudit-policy.json',
                  'json',
                );
              }}
            >
              Export policy
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!customised}
              leadingIcon={<RotateCcw aria-hidden="true" className="size-4" />}
              onClick={() => {
                reset();
                setEditorKey((k) => k + 1);
                toast.info('Policy reset', 'The default policy is active again.');
              }}
            >
              Reset to default
            </Button>
          </div>
        </div>

        <div className="mb-6">
          <h3 className="mb-2 text-sm font-semibold">Start from a preset</h3>
          <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            {POLICY_PRESETS.map((preset) => (
              <li
                key={preset.id}
                className="flex flex-col justify-between gap-3 rounded-xl border border-line/10 bg-surface-2/40 p-4"
              >
                <div>
                  <p className="font-medium text-fg">{preset.name}</p>
                  <p className="mt-1 text-xs text-fg-muted">{preset.description}</p>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  aria-label={`Use preset: ${preset.name}`}
                  onClick={() => {
                    load(preset.policy, `${preset.name} is now active.`);
                  }}
                >
                  Use preset
                </Button>
              </li>
            ))}
          </ul>
        </div>

        {capabilities && capabilities.profiles.length > 0 && (
          <div className="mb-6">
            <h3 className="mb-2 text-sm font-semibold">Server profiles</h3>
            <p className="mb-3 text-xs text-fg-muted">
              Named policies defined on this server (built-in plus any the operator added). Built-in
              profiles are inspired by public guidance; they are starting points, not compliance
              certifications.
            </p>
            <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {capabilities.profiles.map((item) => (
                <li
                  key={item.name}
                  className="flex flex-col justify-between gap-3 rounded-xl border border-line/10 bg-surface-2/40 p-4"
                >
                  <div>
                    <p className="flex flex-wrap items-center gap-2 font-medium text-fg">
                      {item.title}
                      {!item.builtin && (
                        <Badge size="sm" tone="secondary">
                          Custom
                        </Badge>
                      )}
                    </p>
                    <p className="mt-1 text-xs text-fg-muted">{item.description}</p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    aria-label={`Use profile: ${item.title}`}
                    onClick={() => void applyProfile(item.name, item.title)}
                  >
                    Use profile
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}

        <PolicyEditor key={editorKey} policy={policy} onChange={setPolicy} />

        <div className="mt-6">
          <Disclosure summary="Import a policy from a JSON file">
            <div className="space-y-3">
              <FileDrop
                label="Choose a policy .json file"
                hint="Unknown fields are rejected. Missing fields use the defaults."
                accept=".json,application/json"
                onFile={(file) => void onFile(file)}
              />
              {importError && <Alert tone="danger">{importError}</Alert>}
            </div>
          </Disclosure>
        </div>
      </Card>

      <Card as="section" aria-labelledby="policy-check-h">
        <CardTitle id="policy-check-h" level={2}>
          Check a password
        </CardTitle>
        <CardDescription>
          Checked by the local service against the policy above. The password is never stored or
          logged, and is cleared after the check.
        </CardDescription>
        <form
          onSubmit={(event) => void submit(event)}
          noValidate
          autoComplete="off"
          aria-busy={loading || undefined}
          className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-2"
        >
          <Field label="Password to check" error={passwordError ?? undefined} required>
            <PasswordInput
              ref={passwordRef}
              value={password}
              name="policy-secret"
              disabled={loading}
              onChange={(event) => {
                setPassword(event.target.value);
                if (passwordError) setPasswordError(null);
              }}
            />
          </Field>
          <Field
            label="Personal details (optional)"
            hint="One per line. Used only if the policy rejects personal details."
            error={personalError ?? undefined}
          >
            <Textarea
              rows={2}
              value={personalText}
              disabled={loading}
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              onChange={(event) => {
                setPersonalText(event.target.value);
              }}
            />
          </Field>
          <div className="lg:col-span-2">
            <Button
              type="submit"
              loading={loading}
              leadingIcon={<ScrollText aria-hidden="true" className="size-4" />}
            >
              {loading ? 'Checking...' : 'Check password'}
            </Button>
          </div>
        </form>
      </Card>

      {action.state.status === 'error' && (
        <ErrorPanel
          error={action.state.error}
          onRetry={() => void submit()}
          onUseDemo={showDemo}
          onDismiss={action.cancel}
        />
      )}

      <section
        aria-labelledby="policy-result-h"
        aria-busy={loadingResult || undefined}
        className="space-y-4"
      >
        {view || loadingResult ? (
          <h2
            id="policy-result-h"
            ref={resultHeading}
            tabIndex={-1}
            className="text-xl font-semibold outline-none"
          >
            {loadingResult ? 'Checking...' : 'Result'}
          </h2>
        ) : (
          <h2 id="policy-result-h" className="sr-only">
            Result
          </h2>
        )}
        {loadingResult && (
          <Card>
            <div className="mb-4 flex items-center gap-3 text-sm text-fg-muted">
              <Spinner label="Checking the password" size="sm" />
              Checking locally...
            </div>
            <SkeletonText lines={4} />
          </Card>
        )}
        {!loadingResult && view && (
          <Card>
            {view.source === 'demo' && (
              <DemoBanner
                className="mb-5"
                reason="The service is not connected."
                onExit={() => {
                  setView(null);
                }}
              />
            )}
            <PolicyResult
              result={view.result}
              policy={view.policy as Record<string, unknown>}
              source={view.source}
            />
          </Card>
        )}
      </section>
    </div>
  );
}
