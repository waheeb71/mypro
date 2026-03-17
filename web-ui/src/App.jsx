import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './hooks/useAuth';

// Layout
import Shell from './layout/Shell';

// Pages
import Login     from './modules/auth/Login';
import Dashboard from './modules/dashboard/Dashboard';
import Firewall  from './modules/firewall/Firewall';
import WAF       from './modules/waf/WAF';
import IDSIPS    from './modules/ids_ips/IDSIPS';
import System    from './modules/system/System';
import VPN       from './modules/vpn/VPN';
import DNS       from './modules/dns_security/DNS';

// Shared CSS
import './modules/firewall/Firewall.css'; // contains shared .module-page, .icon-btn etc.

const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 10_000 } } });

// Guard: redirect to /login if not authenticated
function PrivateRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public */}
            <Route path="/login" element={<Login />} />

            {/* Protected — all inside Shell */}
            <Route
              path="/"
              element={
                <PrivateRoute>
                  <Shell />
                </PrivateRoute>
              }
            >
              <Route index          element={<Dashboard />} />
              <Route path="firewall" element={<Firewall />} />
              <Route path="waf"      element={<WAF />} />
              <Route path="ids-ips"  element={<IDSIPS />} />
              <Route path="vpn"      element={<VPN />} />
              <Route path="dns"      element={<DNS />} />
              <Route path="system"   element={<System />} />

              {/* Catch-all */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}
