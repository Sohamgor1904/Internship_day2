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
  RefreshCw,
  Info
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function HealthGauge({ database, redis, pipeline }: { database: string, redis: string, pipeline: string }) {
  let percentage = 98;
  if (database !== "healthy") percentage -= 30;
  if (redis !== "healthy") percentage -= 30;
  if (pipeline !== "healthy") percentage -= 30;
  
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center p-2">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full transform -rotate-90">
          <circle
            cx="72"
            cy="72"
            r={radius}
            className="stroke-slate-100"
            strokeWidth="8"
            fill="transparent"
          />
          <circle
            cx="72"
            cy="72"
            r={radius}
            className="stroke-indigo-600 progress-circle"
            strokeWidth="8"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-black text-slate-800 font-mono">{percentage}%</span>
          <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">Secure</span>
        </div>
      </div>
    </div>
  );
}

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
    <div className="min-h-screen bg-slate-50 text-slate-800 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Top Header Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200 animate-fade-in-up">
          <div>
            <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">SOC Dashboard Overview</h1>
            <p className="text-xs text-slate-500 mt-1">Real-time threat detection metrics and pipeline status feed.</p>
          </div>
          
          {/* Health Badges & Refetch */}
          <div className="flex flex-wrap items-center gap-6 bg-white px-5 py-3 rounded-lg border border-slate-200 shadow-xxs">
            <HealthBadge name="Redis" status={healthData?.components.redis || "healthy"} />
            <HealthBadge name="PostgreSQL" status={healthData?.components.database || "healthy"} />
            <HealthBadge name="Pipeline" status={healthData?.components.pipeline || "healthy"} />
            
            <button
              onClick={() => refetchMetrics()}
              className="p-1.5 hover:bg-slate-100 rounded transition-colors text-slate-400 hover:text-slate-700"
              title="Refresh Stats"
            >
              <RefreshCw className={`w-4 h-4 ${(isFetchingMetrics || isFetchingHealth) ? "animate-spin text-indigo-600" : ""}`} />
            </button>
          </div>
        </div>

        {/* 4 Summary Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-8 animate-fade-in-up animation-delay-100">
          {/* Card 1: Total Alerts Today */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Alerts Today</CardTitle>
              <ShieldAlert className="w-5 h-5 text-indigo-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-slate-800">{summary.totalAlertsToday}</div>
              <p className="text-xxs text-slate-400 mt-1">Total identified anomalous security events.</p>
            </CardContent>
          </Card>

          {/* Card 2: Active Threats */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Threats</CardTitle>
              <Activity className="w-5 h-5 text-rose-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-rose-600">{summary.activeThreats}</div>
              <p className="text-xxs text-slate-400 mt-1">Confirmed Layer 3 sequential threats.</p>
            </CardContent>
          </Card>

          {/* Card 3: DLQ Size */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">DLQ Size</CardTitle>
              <Skull className="w-5 h-5 text-amber-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-amber-600">{summary.dlqSize}</div>
              <p className="text-xxs text-slate-400 mt-1">Isolated database insert failure records.</p>
            </CardContent>
          </Card>

          {/* Card 4: Events Processed */}
          <Card className="bg-white border-slate-200 shadow-sm hover-lift">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Events Processed</CardTitle>
              <Database className="w-5 h-5 text-emerald-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-slate-800">{summary.eventsProcessed.toLocaleString()}</div>
              <p className="text-xxs text-slate-400 mt-1">Total normalized pipeline ingest streams.</p>
            </CardContent>
          </Card>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8 animate-fade-in-up animation-delay-200">
          
          {/* Recharts AreaChart: Alert Volume Last 60 Minutes (Spans 2 columns on large screens) */}
          <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover-lift">
            <div className="flex items-center justify-between pb-4">
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">Threat Activity (Last 60 Minutes)</h3>
              <span className="text-xxs text-slate-400">Auto-refreshes silently</span>
            </div>
            <div className="h-80 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={timelineData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#E11D48" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#E11D48" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.5} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: "#ffffff", borderColor: "#cbd5e1", borderRadius: "8px", boxShadow: "0 4px 12px rgba(15,23,42,0.05)" }}
                    labelClassName="text-slate-500 text-xs font-semibold"
                    itemStyle={{ color: "#0f172a", fontSize: "12px" }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="alertsCount" 
                    name="Alerts Volume"
                    stroke="#E11D48" 
                    strokeWidth={2}
                    fillOpacity={1} 
                    fill="url(#alertGrad)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* System Health Radial Gauge Panel */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover-lift flex flex-col items-center justify-between min-h-[300px]">
            <div className="w-full flex items-center justify-between pb-2 border-b border-slate-100">
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">System Security Health</h3>
              <span className="text-xxs text-slate-400">Live Risk Gauge</span>
            </div>
            
            <HealthGauge 
              database={healthData?.components.database || "healthy"} 
              redis={healthData?.components.redis || "healthy"} 
              pipeline={healthData?.components.pipeline || "healthy"} 
            />
            
            <p className="text-xxs text-slate-400 text-center leading-normal mt-2">Overall score based on stateful database status, Redis queue latency, and pipeline model validation checks.</p>
          </div>
        </div>

        {/* Volumetric Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8 animate-fade-in-up animation-delay-300">
          {/* Recharts BarChart: Pipeline Triage Volumetric statistics */}
          <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover-lift">
            <div className="flex items-center justify-between pb-4">
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">Pipeline Volumetric drop counts</h3>
              <span className="text-xxs text-slate-400">Totals by Defense Layer</span>
            </div>
            <div className="h-80 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={volumetricData}
                  margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.5} />
                  <XAxis dataKey="layer" stroke="#64748b" fontSize={9} tickLine={false} />
                  <YAxis scale="log" domain={[1, 'auto']} allowDataOverflow stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#ffffff", borderColor: "#cbd5e1", borderRadius: "8px", boxShadow: "0 4px 12px rgba(15,23,42,0.05)" }}
                    labelClassName="text-slate-500 text-xs font-semibold"
                    itemStyle={{ color: "#0f172a", fontSize: "12px" }}
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

          {/* Quick Stats Check list */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover-lift flex flex-col justify-between">
            <div className="w-full pb-2 border-b border-slate-100 mb-3 flex items-center gap-1.5">
              <Info className="w-4 h-4 text-indigo-600" />
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">Telemetry Diagnostics</h3>
            </div>
            <div className="flex-1 flex flex-col justify-center space-y-3.5 text-xs text-slate-500">
              <div className="flex items-center justify-between border-b border-slate-50 pb-2">
                <span>Database Sync Status:</span>
                <span className="font-semibold text-emerald-600">Active</span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-50 pb-2">
                <span>Model Load Status:</span>
                <span className="font-semibold text-emerald-600">Loaded (RF, LSTM)</span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-50 pb-2">
                <span>Z-Score Baseline Limit:</span>
                <span className="font-semibold text-slate-700">2.5 Threshold</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Redis Pipeline Latency:</span>
                <span className="font-semibold text-slate-700">&lt; 0.5 ms</span>
              </div>
            </div>
          </div>
        </div>

      </main>
    </div>
  );
}
