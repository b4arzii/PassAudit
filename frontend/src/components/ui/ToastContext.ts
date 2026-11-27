import { createContext } from 'react';
import type { ReactNode } from 'react';

export type ToastTone = 'info' | 'success' | 'warning' | 'danger';

export interface ToastOptions {
  title: string;
  description?: ReactNode;
  tone?: ToastTone;
  /** Milliseconds before auto-dismiss; `null` keeps it until dismissed. Default 6000 (danger 10000). */
  duration?: number | null;
  action?: { label: string; onClick: () => void };
}

export interface ToastApi {
  show: (options: ToastOptions) => string;
  info: (title: string, description?: ReactNode) => string;
  success: (title: string, description?: ReactNode) => string;
  warning: (title: string, description?: ReactNode) => string;
  error: (title: string, description?: ReactNode) => string;
  dismiss: (id: string) => void;
  dismissAll: () => void;
}

export const ToastContext = createContext<ToastApi | null>(null);
