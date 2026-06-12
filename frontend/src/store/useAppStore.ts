import { create } from "zustand";
import { AlertObject } from "../mocks/alertsMock";

interface AppState {
  activeIPFilter: string | null;
  selectedAlert: AlertObject | null;
  sidebarCollapsed: boolean;
  setActiveIPFilter: (ip: string | null) => void;
  setSelectedAlert: (alert: AlertObject | null) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeIPFilter: null,
  selectedAlert: null,
  sidebarCollapsed: false,
  setActiveIPFilter: (ip) => set({ activeIPFilter: ip }),
  setSelectedAlert: (alert) => set({ selectedAlert: alert }),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
}));
