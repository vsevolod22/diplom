import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HomePage } from '@/pages/home/HomePage';

describe('HomePage', () => {
  it('renders the project heading', () => {
    render(<HomePage />);
    expect(screen.getByRole('heading', { name: 'Диплом' })).toBeTruthy();
  });
});
