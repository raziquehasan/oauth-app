import type LoginData from "@/models/LoginData";
import type LoginResponseData from "@/models/LoginResponseData";
import type User from "@/models/User";
import { loginUser, logoutUser } from "@/services/AuthService";
import { create } from "zustand";
import { persist } from "zustand/middleware";

const LOCAL_KEY = "app_state";

type AuthState = {
  accessToken: string | null;
  user: User | null;
  authStatus: boolean;
  authLoading: boolean;

  login: (loginData: LoginData) => Promise<LoginResponseData>;
  loginWithToken: (accessToken: string, user: User) => void;
  logout: (silent?: boolean) => void;
  checkLogin: () => boolean;

  changeLocalLoginData: (
    accessToken: string,
    user: User,
    authStatus: boolean
  ) => void;
};

const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      user: null,
      authStatus: false,
      authLoading: false,

      changeLocalLoginData: (accessToken, user, authStatus) => {
        set({ accessToken, user, authStatus });
      },

      login: async (loginData) => {
        set({ authLoading: true });
        try {
          const loginResponseData = await loginUser(loginData);
          set({
            accessToken: loginResponseData.accessToken,
            user: loginResponseData.user,
            authStatus: true
          });
          return loginResponseData;
        } finally {
          set({ authLoading: false });
        }
      },

      // 🔥 FOR OAUTH LOGIN
      loginWithToken: (accessToken, user) => {
        set({
          accessToken,
          user,
          authStatus: true,
          authLoading: false
        });
      },

      logout: async (silent = false) => {
        try {
          set({ authLoading: true });
          if (!silent) {
            await logoutUser();
          }
        } finally {
          set({
            accessToken: null,
            user: null,
            authLoading: false,
            authStatus: false
          });
        }
      },

      checkLogin: () => {
        return !!(get().accessToken && get().authStatus);
      }
    }),
    { name: LOCAL_KEY }
  )
);

export default useAuth;
