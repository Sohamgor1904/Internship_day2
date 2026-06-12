import { useState } from "react";
import { useAppStore } from "../store/useAppStore";
import { X, Shield, Cpu, Activity, Database, Braces } from "lucide-react";
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ReferenceLine 
} from "recharts";
import { LayerBadge } from "./LayerBadge";
import { format } from "date-fns";

export function AlertDrawer() {
  const { selectedAlert, setSelectedAlert } = useAppStore();
  const [showRawJson, setShowRawJson] = useState(false);

  if (!selectedAlert) return null;

  // Format SHAP explanations data for horizontal bar chart
  const shapData = selectedAlert.explanations.map(exp => ({
    name: exp.feature_name,
    value: parseFloat(exp.shap_value.toFixed(4)),
    fill: exp.shap_value >= 0 ? "#ef4444" : "#10b981" // Red for positive attribution, green for negative
  }));

  // Format bytes helper
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Overlay */}
      <div 
        className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
        onClick={() => {
          setSelectedAlert(null);
          setShowRawJson(false);
        }}
      />

      {/* Slide-out Panel */}
      <div className="relative w-full max-w-xl h-full bg-slate-950 border-l border-slate-800 shadow-2xl flex flex-col z-10 text-slate-100 animate-in slide-in-from-right duration-300">
        
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-bold tracking-tight">Threat Investigator</h2>
          </div>
          <button 
            onClick={() => {
              setSelectedAlert(null);
              setShowRawJson(false);
            }}
            className="p-1 hover:bg-slate-800 rounded transition-colors text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          
          {/* Layer Verdict & Confidence */}
          <div className="bg-slate-900/50 rounded-lg border border-slate-800/80 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-slate-400">Classification</span>
              <span className="text-sm font-semibold text-rose-400 uppercase tracking-wider">{selectedAlert.classification}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-slate-400">Pipeline Layer</span>
              <LayerBadge layer={selectedAlert.l3_threat_prob >= 0.5 ? 3 : selectedAlert.l2_threat_prob >= 0.5 ? 2 : 1} />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-slate-400">Threat Confidence Score</span>
              <span className="text-sm font-bold text-white">
                {Math.max(selectedAlert.l1_anomaly_score / 10, selectedAlert.l2_threat_prob, selectedAlert.l3_threat_prob).toLocaleString(undefined, { style: "percent", minimumFractionDigits: 1 })}
              </span>
            </div>
          </div>

          {/* OCSF Event Fields */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
              <Database className="w-4 h-4" />
              OCSF Schema Metadata
            </h3>
            
            <div className="grid grid-cols-2 gap-3 bg-slate-900/30 p-4 rounded-lg border border-slate-800/50 text-sm">
              <div>
                <span className="block text-xs text-slate-500">Source Endpoint</span>
                <span className="font-mono text-slate-200">{selectedAlert.src_ip}:{selectedAlert.src_port}</span>
              </div>
              <div>
                <span className="block text-xs text-slate-500">Destination Endpoint</span>
                <span className="font-mono text-slate-200">{selectedAlert.dst_ip}:{selectedAlert.dst_port}</span>
              </div>
              <div className="mt-2">
                <span className="block text-xs text-slate-500">Protocol</span>
                <span className="uppercase font-semibold text-slate-300">{selectedAlert.protocol}</span>
              </div>
              <div className="mt-2">
                <span className="block text-xs text-slate-500">Timestamp</span>
                <span className="text-slate-300">
                  {format(new Date(selectedAlert.timestamp), "yyyy-MM-dd HH:mm:ss")}
                </span>
              </div>
              <div className="mt-2">
                <span className="block text-xs text-slate-500">Data Transferred</span>
                <span className="text-slate-300">
                  In: {formatBytes(selectedAlert.bytes_in)} | Out: {formatBytes(selectedAlert.bytes_out)}
                </span>
              </div>
              <div className="mt-2">
                <span className="block text-xs text-slate-500">Model Version</span>
                <span className="font-mono text-slate-300">{selectedAlert.model_version}</span>
              </div>
            </div>
          </div>

          {/* SHAP Attributions Horizontal Bar Chart */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-4 h-4" />
              SHAP Attributions (Layer 2 RF Explainability)
            </h3>
            <div className="bg-slate-900/30 p-4 rounded-lg border border-slate-800/50">
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    layout="vertical"
                    data={shapData}
                    margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                  >
                    <XAxis type="number" stroke="#94a3b8" fontSize={10} />
                    <YAxis 
                      dataKey="name" 
                      type="category" 
                      stroke="#94a3b8" 
                      fontSize={9}
                      tickLine={false}
                      width={100}
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155" }}
                      labelClassName="text-slate-400 text-xs font-semibold"
                      itemStyle={{ color: "#f8fafc", fontSize: "12px" }}
                    />
                    <ReferenceLine x={0} stroke="#475569" />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="flex justify-between items-center text-xs mt-2 text-slate-500 px-2">
                <span>← Reduces Threat Risk (Benign)</span>
                <span>Increases Threat Risk (Malicious) →</span>
              </div>
            </div>
          </div>

          {/* Layer Verdicts Breakdowns */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-4 h-4" />
              Pipeline Telemetry
            </h3>
            
            <div className="bg-slate-900/30 p-4 rounded-lg border border-slate-800/50 space-y-3 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">L1 Anomaly Score</span>
                <span className="font-mono font-semibold">{selectedAlert.l1_anomaly_score.toFixed(2)}</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div 
                  className="bg-yellow-400 h-1.5 rounded-full" 
                  style={{ width: `${Math.min(100, (selectedAlert.l1_anomaly_score / 5) * 100)}%` }} 
                />
              </div>

              <div className="flex justify-between items-center pt-2">
                <span className="text-slate-400">L2 Random Forest Probability</span>
                <span className="font-mono font-semibold">{selectedAlert.l2_threat_prob.toLocaleString(undefined, { style: "percent" })}</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div 
                  className="bg-orange-500 h-1.5 rounded-full" 
                  style={{ width: `${selectedAlert.l2_threat_prob * 100}%` }} 
                />
              </div>

              <div className="flex justify-between items-center pt-2">
                <span className="text-slate-400">L3 LSTM Sequential Probability</span>
                <span className="font-mono font-semibold">{selectedAlert.l3_threat_prob.toLocaleString(undefined, { style: "percent" })}</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5">
                <div 
                  className="bg-red-500 h-1.5 rounded-full" 
                  style={{ width: `${selectedAlert.l3_threat_prob * 100}%` }} 
                />
              </div>
            </div>
          </div>

          {/* Raw JSON Toggle */}
          <div className="space-y-3 pt-2">
            <button
              onClick={() => setShowRawJson(!showRawJson)}
              className="flex items-center gap-1.5 text-sm font-semibold text-slate-400 hover:text-white transition-colors"
            >
              <Braces className="w-4 h-4 text-indigo-400" />
              {showRawJson ? "Hide Raw OCSF Payload" : "View Raw OCSF Payload"}
            </button>

            {showRawJson && (
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs text-indigo-300 overflow-x-auto max-h-60">
                <pre>{JSON.stringify(selectedAlert, null, 2)}</pre>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
