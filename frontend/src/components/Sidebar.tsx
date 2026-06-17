import { NavLink, Link } from "react-router-dom";
import { useAppStore } from "../store/useAppStore";
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Search, 
  Skull, 
  ChevronLeft, 
  ChevronRight, 
  Shield,
  BarChart3
} from "lucide-react";

export function Sidebar() {
  const { sidebarCollapsed, setSidebarCollapsed } = useAppStore();

  const navItems = [
    { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { path: "/alerts", label: "Threat Alerts", icon: ShieldAlert },
    { path: "/anomalies", label: "Anomaly Explorer", icon: Search },
    { path: "/dlq", label: "DLQ Monitor", icon: Skull },
    { path: "/performance", label: "Model Performance", icon: BarChart3 },
  ];

  return (
    <aside 
      className={`fixed top-0 left-0 h-screen bg-white border-r border-slate-200 text-slate-700 flex flex-col justify-between transition-all duration-300 z-40 ${
        sidebarCollapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Top Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-200">
          {!sidebarCollapsed && (
            <Link to="/" className="flex items-center gap-2 font-bold text-lg text-slate-900 tracking-wider">
              <Shield className="w-5 h-5 text-indigo-600 fill-indigo-600/10" />
              <span>THREAT<span className="text-indigo-600">PULSE</span></span>
            </Link>
          )}
          {sidebarCollapsed && (
            <Link to="/" className="mx-auto text-indigo-600">
              <Shield className="w-6 h-6 fill-indigo-600/10" />
            </Link>
          )}
          <button 
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="p-1 hover:bg-slate-100 rounded transition-colors text-slate-400 hover:text-slate-700"
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
                      ? "bg-slate-100 text-indigo-600 border-l-2 border-indigo-600 shadow-xxs" 
                      : "text-slate-500 hover:text-indigo-600 hover:bg-slate-50"
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
      <div className="p-4 border-t border-slate-200 bg-slate-50/50">
        <Link 
          to="/" 
          className="flex items-center gap-3 text-xs text-slate-500 hover:text-slate-800 font-medium transition-colors"
        >
          <Shield className="w-4 h-4 text-indigo-500/50" />
          {!sidebarCollapsed && <span>Exit to Landing</span>}
        </Link>
      </div>
    </aside>
  );
}
