import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { LiveScanSession } from '@/features/scans/LiveScanSession';
const HomePage = lazy(() => import('@/pages/home/HomePage').then((module) => ({ default: module.HomePage })));
const DemoAuthPage = lazy(() => import('@/pages/auth/DemoAuthPage').then((module) => ({ default: module.DemoAuthPage })));

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
  return (
    <Suspense fallback={<p role="status">Загружаем интерфейс…</p>}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/register" element={<DemoAuthPage mode="register" />} />
        <Route path="/login" element={<DemoAuthPage mode="login" />} />
        <Route path="/account" element={<DemoAuthPage mode="account" />} />
        <Route path="/scans" element={<LiveScanSession><ScanListPage /></LiveScanSession>} />
        <Route path="/scans/new" element={<LiveScanSession><ScanCreatePage /></LiveScanSession>} />
        <Route path="/scans/:scanId" element={<LiveScanSession><ScanDetailPage /></LiveScanSession>} />
        <Route path="/demo/scans" element={<ScanListPage demo />} />
        <Route path="/demo/scans/new" element={<ScanCreatePage demo />} />
        <Route path="/demo/scans/:scanId" element={<ScanDetailPage demo />} />
        <Route path="*" element={<Navigate to="/scans" replace />} />
      </Routes>
    </Suspense>
  );
}
