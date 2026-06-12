import { NavLink, Link } from "react-router-dom";
import { useAppStore } from "../store/useAppStore";
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Search, 
  Skull, 
  ChevronLeft, 
  ChevronRight, 
  Shield
} from "lucide-react";

export function Sidebar() {
  const { sidebarCollapsed, setSidebarCollapsed } = useAppStore();

  const navItems = [
    { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { path: "/alerts", label: "Threat Alerts", icon: ShieldAlert },
    { path: "/anomalies", label: "Anomaly Explorer", icon: Search },
    { path: "/dlq", label: "DLQ Monitor", icon: Skull },
  ];

  return (
    <aside 
      className={`fixed top-0 left-0 h-screen bg-slate-950 border-r border-slate-800 text-slate-200 flex flex-col justify-between transition-all duration-300 z-40 ${
        sidebarCollapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Top Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800">
          {!sidebarCollapsed && (
            <Link to="/" className="flex items-center gap-2 font-bold text-lg text-white tracking-wider">
              <Shield className="w-5 h-5 text-indigo-400 fill-indigo-400/20" />
              <span>THREAT<span className="text-indigo-400">PULSE</span></span>
            </Link>
          )}
          {sidebarCollapsed && (
            <Link to="/" className="mx-auto text-indigo-400">
              <Shield className="w-6 h-6 fill-indigo-400/20" />
            </Link>
          )}
          <button 
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="p-1 hover:bg-slate-800 rounded transition-colors text-slate-400 hover:text-white"
          >
            {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="mt-6 px-2 space-y-1">
          {navItems.map((item) => {
            const IconComponent = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 ${
                    isActive 
                      ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/20" 
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                  }`
                }
              >
                <IconComponent className="w-5 h-5 flex-shrink-0" />
                {!sidebarCollapsed && <span>{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Logo / Back Home link */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/50">
        <Link 
          to="/" 
          className="flex items-center gap-3 text-xs text-slate-500 hover:text-slate-300 font-medium transition-colors"
        >
          <Shield className="w-4 h-4 text-indigo-500/50" />
          {!sidebarCollapsed && <span>Exit to Landing</span>}
        </Link>
      </div>
    </aside>
  );
}
