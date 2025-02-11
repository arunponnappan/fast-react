import axiosClient from '../api/axiosClient';
import { jwtDecode } from 'jwt-decode';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserProfile {
  id: number;
  email: string;
  username: string;
  role: string;
}

const isTokenExpired = (token: string): boolean => {
  try {
    const decoded = jwtDecode(token);
    return decoded.exp! * 1000 < Date.now();
  } catch {
    return true;
  }
};

export const login = async (credentials: LoginCredentials): Promise<UserProfile> => {
  const formData = new URLSearchParams();
  formData.append('username', credentials.username);
  formData.append('password', credentials.password);

  const response = await axiosClient.post<AuthResponse>('/auth/login', formData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  localStorage.setItem('accessToken', response.data.access_token);
  localStorage.setItem('refreshToken', response.data.refresh_token);

  const userResponse = await axiosClient.get<UserProfile>('/auth/me');
  return userResponse.data;
};

export const refreshAccessToken = async (): Promise<string> => {
  const refreshToken = localStorage.getItem('refreshToken');
  if (!refreshToken || isTokenExpired(refreshToken)) {
    throw new Error('Invalid refresh token');
  }

  const response = await axiosClient.post<AuthResponse>('/auth/refresh');
  localStorage.setItem('accessToken', response.data.access_token);
  localStorage.setItem('refreshToken', response.data.refresh_token);
  
  return response.data.access_token;
};

export const logout = async (): Promise<void> => {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href = '/login';
};