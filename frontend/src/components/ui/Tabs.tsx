import { useId, useRef, useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';

import { cn } from '../../lib/cn.ts';

export interface TabItem {
  id: string;
  label: string;
  /** Small trailing count/badge text. */
  count?: number | undefined;
  content: ReactNode;
}

export interface TabsProps {
  tabs: readonly TabItem[];
  /** Accessible name of the tab list. */
  label: string;
  defaultTab?: string;
  className?: string;
}

/**
 * Accessible tabs (WAI-ARIA tabs pattern): a roving tabindex, Arrow/Home/End keys move and
 * activate, and every panel is labelled by its tab. Inactive panels are not rendered.
 */
export function Tabs({ tabs, label, defaultTab, className }: TabsProps) {
  const base = useId();
  const [active, setActive] = useState(defaultTab ?? tabs[0]?.id ?? '');
  const refs = useRef(new Map<string, HTMLButtonElement>());

  function focusTab(id: string): void {
    setActive(id);
    refs.current.get(id)?.focus();
  }

  function onKeyDown(event: KeyboardEvent, index: number): void {
    const last = tabs.length - 1;
    const target =
      event.key === 'ArrowRight'
        ? (index + 1) % tabs.length
        : event.key === 'ArrowLeft'
          ? (index - 1 + tabs.length) % tabs.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    if (target === null) return;
    event.preventDefault();
    const next = tabs[target];
    if (next) focusTab(next.id);
  }

  const current = tabs.find((t) => t.id === active) ?? tabs[0];

  return (
    <div className={className}>
      <div
        role="tablist"
        aria-label={label}
        className="flex gap-1 overflow-x-auto border-b border-line/10"
      >
        {tabs.map((tab, index) => {
          const selected = tab.id === current?.id;
          return (
            <button
              key={tab.id}
              ref={(node) => {
                if (node) refs.current.set(tab.id, node);
                else refs.current.delete(tab.id);
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`${base}-panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => {
                setActive(tab.id);
              }}
              onKeyDown={(event) => {
                onKeyDown(event, index);
              }}
              className={cn(
                '-mb-px inline-flex h-11 shrink-0 items-center gap-2 border-b-2 px-4 text-sm font-medium transition-colors',
                selected
                  ? 'border-primary text-fg'
                  : 'border-transparent text-fg-muted hover:text-fg',
              )}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className="tabular rounded-full bg-fg/10 px-2 py-0.5 text-xs text-fg-muted">
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>
      {current && (
        <div
          role="tabpanel"
          id={`${base}-panel-${current.id}`}
          aria-labelledby={`${base}-tab-${current.id}`}
          tabIndex={0}
          className="pt-5 outline-offset-4"
        >
          {current.content}
        </div>
      )}
    </div>
  );
}
