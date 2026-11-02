import { lazy, Suspense } from 'react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
import { PasswordResetPage } from '@/pages/auth/PasswordResetPage';
import { SiteLayout } from '../../widgets/layout/SiteLayout';
import { RouteErrorBoundary } from './RouteErrorBoundary';
import { NotFoundPage } from './NotFoundPage';
import { RouteLoading } from '../../shared/ui/RouteLoading';
const HomePage = lazy(() => import('@/pages/home/HomePage').then((module) => ({ default: module.HomePage })));
const DemoAuthPage = lazy(() =>
  import('@/pages/auth/DemoAuthPage').then((module) => ({ default: module.DemoAuthPage })),
);

const ScanListPage = lazy(() =>
  import('@/pages/scans/ScanListPage').then((module) => ({ default: module.ScanListPage })),
);
const ScanCreatePage = lazy(() =>
  import('@/pages/scans/ScanCreatePage').then((module) => ({ default: module.ScanCreatePage })),
);
const ScanDetailPage = lazy(() =>
  import('@/pages/scans/ScanDetailPage').then((module) => ({ default: module.ScanDetailPage })),
);

export function ScanRoutes() {
  const { pathname } = useLocation();
  return (
    <SiteLayout>
      <RouteErrorBoundary key={pathname}>
        <Suspense fallback={<RouteLoading />}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/register" element={<DemoAuthPage mode="register" />} />
            <Route path="/login" element={<DemoAuthPage mode="login" />} />
            <Route path="/account" element={<DemoAuthPage mode="account" />} />
            <Route path="/forgot-password" element={<PasswordResetPage key="request" mode="request" />} />
            <Route path="/reset-password" element={<PasswordResetPage key="confirm" mode="confirm" />} />
            <Route
              path="/scans"
              element={
                <LiveScanSession>
                  <ScanListPage />
                </LiveScanSession>
              }
            />
            <Route
              path="/scans/new"
              element={
                <LiveScanSession>
                  <ScanCreatePage />
                </LiveScanSession>
              }
            />
            <Route
              path="/scans/:scanId"
              element={
                <LiveScanSession>
                  <ScanDetailPage />
                </LiveScanSession>
              }
            />
            <Route path="/demo/scans" element={<ScanListPage demo />} />
            <Route path="/demo/scans/new" element={<ScanCreatePage demo />} />
            <Route path="/demo/scans/:scanId" element={<ScanDetailPage demo />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </RouteErrorBoundary>
    </SiteLayout>
  );
}
