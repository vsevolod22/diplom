import type { ButtonHTMLAttributes, HTMLAttributes } from 'react';
import { clsx } from 'clsx';

export function Card({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return <div className={clsx('scan-card', className)} {...props} />;
}

export function Badge({
  tone = 'neutral',
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: 'neutral' | 'info' | 'warning' | 'danger' }) {
  return <span className={clsx('scan-badge', `scan-badge--${tone}`, className)} {...props} />;
}

export function Button({
  className,
  variant = 'primary',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' }) {
  return <button className={clsx('scan-button', `scan-button--${variant}`, className)} {...props} />;
}

export function Alert({
  tone = 'warning',
  className,
  ...props
}: HTMLAttributes<HTMLDivElement> & { tone?: 'warning' | 'danger' | 'neutral' }) {
  return <div className={clsx('scan-alert', `scan-alert--${tone}`, className)} {...props} />;
}
