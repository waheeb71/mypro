/**
 * Auth Context — global login state + JWT management
 */
import { createContext, useContext, useState, useCallback } from 'react';
import { authApi } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem('CyberNexus_user');
    return raw ? JSON.parse(raw) : null;
  });

  const login = useCallback(async (username, password) => {
    const { data } = await authApi.login({ username, password });
    localStorage.setItem('CyberNexus_token', data.access_token);
    const me = { username, role: data.role };
    localStorage.setItem('CyberNexus_user', JSON.stringify(me));
    setUser(me);
    return data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('CyberNexus_token');
    localStorage.removeItem('CyberNexus_user');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
