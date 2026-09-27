import { createRoot } from 'react-dom/client';
import { AppProviders } from '@/app/providers/AppProviders';
import { HomePage } from '@/pages/home/HomePage';
import '@/app/styles/index.css';

const root = document.getElementById('root');
if (!root) throw new Error('Root element is missing');

createRoot(root).render(
  <AppProviders>
    <HomePage />
  </AppProviders>,
);
