import { AlertTriangle, CheckCircle2, Info, OctagonAlert } from 'lucide-react';

export type AlertTone = 'info' | 'success' | 'warning' | 'danger';

export const TONE_STYLES: Record<AlertTone, { icon: typeof Info; box: string; text: string }> = {
  info: { icon: Info, box: 'border-accent/30 bg-accent/10', text: 'text-accent' },
  success: { icon: CheckCircle2, box: 'border-success/30 bg-success/10', text: 'text-success' },
  warning: { icon: AlertTriangle, box: 'border-warning/30 bg-warning/10', text: 'text-warning' },
  danger: { icon: OctagonAlert, box: 'border-danger/30 bg-danger/10', text: 'text-danger' },
};
