import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAlerts } from "../api/alertsApi";
import { Sidebar } from "../components/Sidebar";
import { AlertDrawer } from "../components/AlertDrawer";
import { LayerBadge } from "../components/LayerBadge";
import { useAppStore } from "../store/useAppStore";
import { format } from "date-fns";
import { Search, SlidersHorizontal, RefreshCw } from "lucide-react";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function Alerts() {
  const { sidebarCollapsed, setSelectedAlert } = useAppStore();

  // Filters State
  const [ipSearch, setIpSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [layerFilter, setLayerFilter] = useState("all");

  // TanStack Query alerts list
  const { data: alerts = [], isFetching, refetch } = useQuery({
    queryKey: ["alertsList"],
    queryFn: fetchAlerts,
    refetchInterval: 30000 // 30s auto-refresh
  });

  // Client-side filtering logic
  const filteredAlerts = alerts.filter((alert) => {
    const matchesIp = 
      alert.src_ip.toLowerCase().includes(ipSearch.toLowerCase()) ||
      alert.dst_ip.toLowerCase().includes(ipSearch.toLowerCase());
      
    const matchesProtocol = 
      protocolFilter === "all" || 
      alert.protocol.toLowerCase() === protocolFilter.toLowerCase();

    // Determine alert layer based on probabilities
    const alertLayer = alert.l3_threat_prob >= 0.5 ? 3 : alert.l2_threat_prob >= 0.5 ? 2 : 1;
    const matchesLayer = 
      layerFilter === "all" || 
      alertLayer === parseInt(layerFilter, 10);

    return matchesIp && matchesProtocol && matchesLayer;
  });

  // Helper to extract top SHAP feature name
  const getTopShapFeature = (alert: any) => {
    if (!alert.explanations || alert.explanations.length === 0) return "N/A";
    // Sort explanations by absolute value of SHAP value to get the most influential feature
    const sorted = [...alert.explanations].sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value));
    return sorted[0].feature_name;
  };

  // Helper to calculate confidence score
  const calculateConfidence = (alert: any) => {
    const score = Math.max(alert.l1_anomaly_score / 10, alert.l2_threat_prob, alert.l3_threat_prob);
    return score.toLocaleString(undefined, { style: "percent", minimumFractionDigits: 0 });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Header */}
        <div className="flex items-center justify-between pb-6 border-b border-slate-800">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Threat Investigator Panel</h1>
            <p className="text-xs text-slate-400 mt-1">Review, filter, and inspect stateful OCSF telemetry alerts.</p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? "animate-spin text-indigo-400" : ""}`} />
          </button>
        </div>

        {/* Filter Toolbar Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-8 p-4 bg-slate-900/40 rounded-xl border border-slate-800/80 items-center">
          <div className="md:col-span-2 relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <Input 
              placeholder="Search by IP address..." 
              value={ipSearch}
              onChange={(e) => setIpSearch(e.target.value)}
              className="pl-9 bg-slate-950 border-slate-800 text-slate-100 focus-visible:ring-indigo-600 focus-visible:ring-offset-0 focus-visible:ring-1"
            />
          </div>

          <div>
            <Select value={protocolFilter} onValueChange={setProtocolFilter}>
              <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200 focus:ring-indigo-600 focus:ring-offset-0 focus:ring-1">
                <SelectValue placeholder="Protocol" />
              </SelectTrigger>
              <SelectContent className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectItem value="all">All Protocols</SelectItem>
                <SelectItem value="tcp">TCP</SelectItem>
                <SelectItem value="udp">UDP</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Select value={layerFilter} onValueChange={setLayerFilter}>
              <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200 focus:ring-indigo-600 focus:ring-offset-0 focus:ring-1">
                <SelectValue placeholder="Layer" />
              </SelectTrigger>
              <SelectContent className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectItem value="all">All Layers</SelectItem>
                <SelectItem value="1">Layer 1 (Triage)</SelectItem>
                <SelectItem value="2">Layer 2 (RF Classifier)</SelectItem>
                <SelectItem value="3">Layer 3 (LSTM)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="mt-6 bg-slate-900/20 border border-slate-800 rounded-xl overflow-hidden">
          <Table>
            <TableHeader className="bg-slate-900/60 border-b border-slate-800">
              <TableRow className="hover:bg-transparent border-slate-800">
                <TableHead className="text-slate-400 font-semibold py-4">Timestamp</TableHead>
                <TableHead className="text-slate-400 font-semibold">Source IP</TableHead>
                <TableHead className="text-slate-400 font-semibold">Destination IP</TableHead>
                <TableHead className="text-slate-400 font-semibold">Protocol</TableHead>
                <TableHead className="text-slate-400 font-semibold">Flagged Layer</TableHead>
                <TableHead className="text-slate-400 font-semibold">Confidence</TableHead>
                <TableHead className="text-slate-400 font-semibold">Top SHAP Feature</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <TableRow 
                    key={alert.id}
                    onClick={() => setSelectedAlert(alert)}
                    className="cursor-pointer border-slate-800 hover:bg-slate-900/50 transition-colors"
                  >
                    <TableCell className="font-mono text-xs text-slate-300 py-4.5">
                      {format(new Date(alert.timestamp), "yyyy-MM-dd HH:mm:ss")}
                    </TableCell>
                    <TableCell className="font-mono text-sm text-slate-200 font-medium">
                      {alert.src_ip}:{alert.src_port}
                    </TableCell>
                    <TableCell className="font-mono text-sm text-slate-300">
                      {alert.dst_ip}:{alert.dst_port}
                    </TableCell>
                    <TableCell className="uppercase text-xs font-semibold text-slate-400">
                      {alert.protocol}
                    </TableCell>
                    <TableCell>
                      <LayerBadge layer={alert.l3_threat_prob >= 0.5 ? 3 : alert.l2_threat_prob >= 0.5 ? 2 : 1} />
                    </TableCell>
                    <TableCell className="font-bold text-slate-200 text-sm">
                      {calculateConfidence(alert)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-indigo-300 font-semibold">
                      {getTopShapFeature(alert)}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12 text-slate-500">
                    No threat alerts match your current filter selection.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        {/* Slide-out Threat Details Investigation Drawer */}
        <AlertDrawer />

      </main>
    </div>
  );
}
