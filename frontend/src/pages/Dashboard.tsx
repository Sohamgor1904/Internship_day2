import { useQuery } from "@tanstack/react-query";
import { fetchDashboardMetrics } from "../api/metricsApi";
import { fetchHealthStatus } from "../api/healthApi";
import { Sidebar } from "../components/Sidebar";
import { HealthBadge } from "../components/HealthBadge";
import { useAppStore } from "../store/useAppStore";
import { 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from "recharts";
import { 
  ShieldAlert, 
  Activity, 
  Skull, 
  Database, 
  RefreshCw 
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function Dashboard() {
  const { sidebarCollapsed } = useAppStore();

  // TanStack Query for Metrics & Health Status
  const { data: metricsData, isFetching: isFetchingMetrics, refetch: refetchMetrics } = useQuery({
    queryKey: ["dashboardMetrics"],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 30000 // 30s auto-refresh
  });

  const { data: healthData, isFetching: isFetchingHealth } = useQuery({
    queryKey: ["healthStatus"],
    queryFn: fetchHealthStatus,
    refetchInterval: 30000 // 30s auto-refresh
  });

  // KPI Metrics data
  const summary = metricsData?.summary || {
    totalAlertsToday: 142,
    activeThreats: 18,
    dlqSize: 4,
    eventsProcessed: 1042392
  };

  const timelineData = metricsData?.timeline || [];
  const volumetricData = metricsData?.volumetric || [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Top Header Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">SOC Dashboard Overview</h1>
            <p className="text-xs text-slate-400 mt-1">Real-time threat detection metrics and pipeline status feed.</p>
          </div>
          
          {/* Health Badges & Refetch */}
          <div className="flex flex-wrap items-center gap-6 bg-slate-900/50 px-5 py-3 rounded-lg border border-slate-800">
            <HealthBadge name="Redis" status={healthData?.components.redis || "healthy"} />
            <HealthBadge name="PostgreSQL" status={healthData?.components.database || "healthy"} />
            <HealthBadge name="Pipeline" status={healthData?.components.pipeline || "healthy"} />
            
            <button
              onClick={() => refetchMetrics()}
              className="p-1.5 hover:bg-slate-800 rounded transition-colors text-slate-400 hover:text-white"
              title="Refresh Stats"
            >
              <RefreshCw className={`w-4 h-4 ${(isFetchingMetrics || isFetchingHealth) ? "animate-spin text-indigo-400" : ""}`} />
            </button>
          </div>
        </div>

        {/* 4 Summary Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-8">
          {/* Card 1: Total Alerts Today */}
          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Alerts Today</CardTitle>
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-white">{summary.totalAlertsToday}</div>
              <p className="text-xxs text-slate-500 mt-1">Total identified anomalous security events.</p>
            </CardContent>
          </Card>

          {/* Card 2: Active Threats */}
          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Threats</CardTitle>
              <Activity className="w-5 h-5 text-rose-500 animate-pulse" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-rose-400">{summary.activeThreats}</div>
              <p className="text-xxs text-slate-500 mt-1">Confirmed Layer 3 sequential threats.</p>
            </CardContent>
          </Card>

          {/* Card 3: DLQ Size */}
          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">DLQ Size</CardTitle>
              <Skull className="w-5 h-5 text-amber-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-amber-400">{summary.dlqSize}</div>
              <p className="text-xxs text-slate-500 mt-1">Isolated database insert failure records.</p>
            </CardContent>
          </Card>

          {/* Card 4: Events Processed */}
          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Events Processed</CardTitle>
              <Database className="w-5 h-5 text-emerald-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-white">{summary.eventsProcessed.toLocaleString()}</div>
              <p className="text-xxs text-slate-500 mt-1">Total normalized pipeline ingest streams.</p>
            </CardContent>
          </Card>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8">
          
          {/* Recharts AreaChart: Alert Volume Last 60 Minutes (Spans 2 columns on large screens) */}
          <div className="lg:col-span-2 bg-slate-900/30 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between pb-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Threat Activity (Last 60 Minutes)</h3>
              <span className="text-xxs text-slate-500">Auto-refreshes silently</span>
            </div>
            <div className="h-80 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={timelineData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EB0052" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#EB0052" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                    labelClassName="text-slate-400 text-xs font-semibold"
                    itemStyle={{ color: "#f8fafc", fontSize: "12px" }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="alertsCount" 
                    name="Alerts Volume"
                    stroke="#EB0052" 
                    strokeWidth={2}
                    fillOpacity={1} 
                    fill="url(#alertGrad)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recharts BarChart: Pipeline Triage Volumetric statistics */}
          <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between pb-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Pipeline Volumetric drop counts</h3>
              <span className="text-xxs text-slate-500">Totals by Defense Layer</span>
            </div>
            <div className="h-80 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={volumetricData}
                  margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                  <XAxis dataKey="layer" stroke="#64748b" fontSize={9} tickLine={false} />
                  <YAxis scale="log" domain={[1, 'auto']} allowDataOverflow stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                    labelClassName="text-slate-400 text-xs font-semibold"
                    itemStyle={{ color: "#f8fafc", fontSize: "12px" }}
                  />
                  <Bar dataKey="count" name="Event Count">
                    {
                      volumetricData.map((entry, index) => (
                        <Bar key={`cell-${index}`} fill={entry.color} radius={[4, 4, 0, 0]} />
                      ))
                    }
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>

      </main>
    </div>
  );
}
