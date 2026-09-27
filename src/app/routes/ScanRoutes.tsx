import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

const ScanListPage = lazy(() => import('@/pages/scans/ScanListPage').then((module) => ({ default: module.ScanListPage })));
const ScanCreatePage = lazy(() => import('@/pages/scans/ScanCreatePage').then((module) => ({ default: module.ScanCreatePage })));
const ScanDetailPage = lazy(() => import('@/pages/scans/ScanDetailPage').then((module) => ({ default: module.ScanDetailPage })));

export function ScanRoutes() {
  return <Suspense fallback={<p role="status">Загружаем интерфейс…</p>}><Routes>
    <Route path="/" element={<Navigate to="/scans" replace />} />
    <Route path="/scans" element={<ScanListPage />} />
    <Route path="/scans/new" element={<ScanCreatePage />} />
    <Route path="/scans/:scanId" element={<ScanDetailPage />} />
    <Route path="/demo/scans" element={<ScanListPage demo />} />
    <Route path="/demo/scans/new" element={<ScanCreatePage demo />} />
    <Route path="/demo/scans/:scanId" element={<ScanDetailPage demo />} />
    <Route path="*" element={<Navigate to="/scans" replace />} />
  </Routes></Suspense>;
}
