import { useState, useMemo } from "react";
import { Sidebar } from "../components/Sidebar";
import { useAppStore } from "../store/useAppStore";
import { 
  ScatterChart, 
  Scatter, 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  ReferenceLine 
} from "recharts";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Activity, Sliders, Hash, ActivitySquare } from "lucide-react";

// Generate mock statistical timeseries data for Anomaly Explorer
interface MetricTimeseries {
  time: string;
  ip: string;
  anomalyScore: number;
  entropy: number;
  ewmaVolume: number; // bytes
}

const generateAnomalyData = (): MetricTimeseries[] => {
  const ips = ["192.168.1.105", "10.0.2.15", "192.168.1.180", "172.16.10.22", "10.0.4.50", "192.168.1.25"];
  const data: MetricTimeseries[] = [];
  const baseTime = new Date();

  // Generate 24 time intervals (e.g. hourly)
  for (let h = 0; h < 24; h++) {
    const timePoint = new Date(baseTime.getTime() - (23 - h) * 3600 * 1000);
    const timeStr = timePoint.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
    
    for (const ip of ips) {
      // Determine baseline characteristics per IP to make charts look realistic
      let baseScore = 1.0;
      let baseEntropy = 1.2;
      let baseVolume = 5000;

      if (ip === "192.168.1.105") { // DDoS source
        baseScore = h >= 16 && h <= 19 ? 4.9 : 1.2;
        baseEntropy = h >= 16 && h <= 19 ? 0.2 : 1.5; // low entropy during flood port target
        baseVolume = h >= 16 && h <= 19 ? 500000 : 8000;
      } else if (ip === "192.168.1.180") { // Slow Beacon APT
        baseScore = h % 3 === 0 ? 3.2 : 0.8;
        baseEntropy = 2.8; // highly dispersed ports
        baseVolume = 12000;
      } else if (ip === "10.0.2.15") { // Heavy Anomaly Downloader
        baseScore = h === 10 || h === 22 ? 4.2 : 1.1;
        baseEntropy = 1.4;
        baseVolume = h === 10 || h === 22 ? 950000 : 4000;
      }

      // Add small perturbations
      const score = Math.max(0.1, baseScore + (Math.random() * 0.4 - 0.2));
      const entropy = Math.max(0.0, baseEntropy + (Math.random() * 0.3 - 0.15));
      const volume = Math.max(100, baseVolume + Math.floor(Math.random() * 1000 - 500));

      data.push({
        time: timeStr,
        ip,
        anomalyScore: parseFloat(score.toFixed(2)),
        entropy: parseFloat(entropy.toFixed(3)),
        ewmaVolume: volume
      });
    }
  }
  return data;
};

export function Anomalies() {
  const { sidebarCollapsed, activeIPFilter, setActiveIPFilter } = useAppStore();

  const allData = useMemo(() => generateAnomalyData(), []);
  
  // List of distinct IPs for Select filter
  const ipList = ["192.168.1.105", "10.0.2.15", "192.168.1.180", "172.16.10.22", "10.0.4.50", "192.168.1.25"];

  // Filter datasets based on Zustand selection
  const scatterData = useMemo(() => {
    return allData.map(d => {
      const isFiltered = activeIPFilter === null || d.ip === activeIPFilter;
      const isAnomaly = d.anomalyScore >= 2.5;
      return {
        ...d,
        // Plot coordinates
        x: d.time,
        y: d.anomalyScore,
        fill: isFiltered ? (isAnomaly ? "#ef4444" : "#94a3b8") : "rgba(71, 85, 105, 0.15)"
      };
    });
  }, [allData, activeIPFilter]);

  const lineData = useMemo(() => {
    // Group and aggregate entropy data for active IP selection
    const grouped: { [time: string]: { time: string; count: number; sum: number } } = {};
    allData.forEach(d => {
      if (activeIPFilter === null || d.ip === activeIPFilter) {
        if (!grouped[d.time]) {
          grouped[d.time] = { time: d.time, count: 0, sum: 0 };
        }
        grouped[d.time].sum += d.entropy;
        grouped[d.time].count += 1;
      }
    });
    return Object.values(grouped).map(g => ({
      time: g.time,
      entropy: parseFloat((g.sum / g.count).toFixed(3))
    }));
  }, [allData, activeIPFilter]);

  const areaData = useMemo(() => {
    // Group and aggregate EWMA bytes volume data for active IP selection
    const grouped: { [time: string]: { time: string; volume: number } } = {};
    allData.forEach(d => {
      if (activeIPFilter === null || d.ip === activeIPFilter) {
        if (!grouped[d.time]) {
          grouped[d.time] = { time: d.time, volume: 0 };
        }
        grouped[d.time].volume += d.ewmaVolume;
      }
    });
    return Object.values(grouped);
  }, [allData, activeIPFilter]);

  // Format bytes helper
  const formatBytes = (bytes: number) => {
    if (bytes >= 1000000) return (bytes / 1000000).toFixed(1) + " MB";
    if (bytes >= 1000) return (bytes / 1000).toFixed(1) + " KB";
    return bytes + " B";
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Top Header Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Anomaly Explorer</h1>
            <p className="text-xs text-slate-400 mt-1">Deep-dive analysis of Z-Scores, Shannon Entropy, and EWMA flow volumes.</p>
          </div>

          {/* Zustand IP Selector */}
          <div className="flex items-center gap-3 bg-slate-900 border border-slate-800 rounded-lg p-2.5">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1">
              <Sliders className="w-3.5 h-3.5" />
              Source IP Filter:
            </span>
            <Select 
              value={activeIPFilter || "all"} 
              onValueChange={(val) => setActiveIPFilter(val === "all" ? null : val)}
            >
              <SelectTrigger className="w-48 bg-slate-950 border-slate-800 text-slate-200 focus:ring-indigo-600 focus:ring-offset-0 focus:ring-1">
                <SelectValue placeholder="All IPs" />
              </SelectTrigger>
              <SelectContent className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectItem value="all">All IPs</SelectItem>
                {ipList.map(ip => (
                  <SelectItem key={ip} value={ip}>{ip}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Graph Sections Grid */}
        <div className="grid grid-cols-1 gap-8 mt-8">
          
          {/* Chart 1: ScatterChart - Anomaly Score per IP over time */}
          <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-1.5">
              <ActivitySquare className="w-4 h-4 text-indigo-400" />
              Layer 1 Volumetric Anomaly Scores (Z-Score Timeline)
            </h3>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} allowDuplicatedCategory={false} />
                  <YAxis dataKey="y" domain={[0, 6]} stroke="#64748b" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                    labelClassName="text-slate-400 text-xs font-semibold"
                    itemStyle={{ fontSize: "12px" }}
                    cursor={{ strokeDasharray: "3 3", stroke: "#475569" }}
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload as MetricTimeseries;
                        return (
                          <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-xs space-y-1">
                            <p className="font-bold text-white">{data.time}</p>
                            <p className="text-slate-400">Host IP: <span className="font-mono text-indigo-300">{data.ip}</span></p>
                            <p className="text-slate-400">Anomaly Score: <span className={`font-bold ${data.anomalyScore >= 2.5 ? "text-rose-400" : "text-slate-200"}`}>{data.anomalyScore}</span></p>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <ReferenceLine y={2.5} stroke="#ef4444" strokeDasharray="3 3" label={{ value: "Anomaly Threshold (2.5)", fill: "#ef4444", fontSize: 10, position: "top" }} />
                  <Scatter 
                    name="Anomaly Score" 
                    data={scatterData} 
                    fill="#3b82f6"
                    // Customize particle shapes/colors
                    shape={(props: any) => {
                      const { cx, cy, payload } = props;
                      return (
                        <circle 
                          cx={cx} 
                          cy={cy} 
                          r={payload.anomalyScore >= 2.5 ? 6 : 4} 
                          fill={payload.fill}
                          className="transition-all duration-200"
                        />
                      );
                    }}
                  />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center gap-4 text-xxs text-slate-500 mt-2 px-2">
              <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500"/> Critical Anomalies (&ge; 2.5)</div>
              <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-slate-500"/> Normal Baseline Activity</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            {/* Chart 2: LineChart - Shannon Entropy */}
            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-1.5">
                <Hash className="w-4 h-4 text-indigo-400" />
                Shannon Entropy of Destination Ports
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={lineData}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={10} tickLine={false} domain={[0, 4]} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                      labelClassName="text-slate-400 text-xs font-semibold"
                      itemStyle={{ color: "#f8fafc", fontSize: "12px" }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="entropy" 
                      name="Shannon Entropy"
                      stroke="#FF5A00" 
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <p className="text-xxs text-slate-500 mt-2 px-1">
                Lower values indicate traffic targeting a concentrated set of ports (e.g. port scan or DDoS).
              </p>
            </div>

            {/* Chart 3: AreaChart - EWMA Volume */}
            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-indigo-400" />
                EWMA Flow Volume byte trend per host
              </h3>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={areaData}
                    margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                    <YAxis 
                      stroke="#64748b" 
                      fontSize={10} 
                      tickLine={false}
                      tickFormatter={formatBytes}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                      labelClassName="text-slate-400 text-xs font-semibold"
                      itemStyle={{ color: "#f8fafc", fontSize: "12px" }}
                      formatter={(val: any) => [formatBytes(val), "Flow Volume"]}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="volume" 
                      stroke="#10b981" 
                      strokeWidth={2}
                      fillOpacity={1} 
                      fill="url(#volGrad)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <p className="text-xxs text-slate-500 mt-2 px-1">
                Exponentially Weighted Moving Average (EWMA) tracking overall byte flow metrics.
              </p>
            </div>

          </div>

        </div>

      </main>
    </div>
  );
}
