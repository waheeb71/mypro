/**
 * Auth Context — global login state + JWT management
 */
import { createContext, useContext, useState, useCallback } from 'react';
import { authApi } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(() => {
    const raw = localStorage.getItem('ngfw_user');
    return raw ? JSON.parse(raw) : null;
  });

  const login = useCallback(async (username, password) => {
    const { data } = await authApi.login({ username, password });
    localStorage.setItem('ngfw_token', data.access_token);
    const me = { username, role: data.role };
    localStorage.setItem('ngfw_user', JSON.stringify(me));
    setUser(me);
    return data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('ngfw_token');
    localStorage.removeItem('ngfw_user');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
