import { useState, useEffect, useRef } from "react";
import { Sidebar } from "../components/Sidebar";
import { useAppStore } from "../store/useAppStore";
import { 
  Terminal as TerminalIcon, 
  ShieldAlert, 
  FileText, 
  Activity, 
  CheckCircle2, 
  Download, 
  AlertTriangle, 
  Cpu, 
  Layers, 
  Info,
  RefreshCw
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface LogEntry {
  id: number;
  time: string;
  type: "info" | "triage_l1" | "triage_l2" | "alert" | "info_l3";
  content: string;
  explanation: string;
  title: string;
}

const SIMULATED_LOGS: Omit<LogEntry, "id" | "time">[] = [
  {
    type: "info",
    content: "[Producer] Reading logs from dataset 'unsw'...",
    title: "Log Ingestion Initiated",
    explanation: "The pipeline producer has started streaming raw logs from the local UNSW-NB15 dataset. These logs will be mapped to the standardized OCSF Class 4001 schema in real-time."
  },
  {
    type: "info",
    content: "[Consumer] Initializing stream sender client to target http://localhost:8000/api/v1/detect...",
    title: "Client Socket Connected",
    explanation: "The stream sender client has established a socket connection to the FastAPI endpoint to stream the normalized events through the detection layers."
  },
  {
    type: "triage_l1",
    content: "[Triage] Benign flow dropped by L1 filter. Anomaly score: 0.42",
    title: "Layer 1 - Volumetric Filter Drop",
    explanation: "This network flow represents standard background activity. It has an anomaly score of 0.42 (Z-score benchmark), which is well below the escalation threshold of 2.5. It was safely dropped by the Layer 1 statistical state machine without running any ML model, conserving host CPU resources."
  },
  {
    type: "triage_l1",
    content: "[Triage] Benign flow dropped by L1 filter. Anomaly score: 1.15",
    title: "Layer 1 - Volumetric Filter Drop",
    explanation: "This network flow is slightly anomalous but is still classified as normal traffic. The anomaly score is 1.15, below our escalation threshold. It was safely dropped at Layer 1."
  },
  {
    type: "triage_l2",
    content: "[Triage] Benign flow dropped by L2 filter. L2 Prob: 0.28",
    title: "Layer 2 - Contextual Classifier Drop",
    explanation: "The flow exhibited dynamic statistical deviations that caused it to pass Layer 1. However, the Layer 2 Random Forest classifier evaluated its features and determined it has a low threat probability (28%), dropping it before invoking Layer 3 LSTM sequential checks."
  },
  {
    type: "alert",
    content: "[ALERT] [Threat Detected!] Type: Exploit | L2 Prob: 0.98 | L3 Prob: 0.95 | Top SHAP reasons: ['dst_port', 'bytes_in']",
    title: "Layer 2 & 3 - High Fidelity Threat Alert",
    explanation: "CRITICAL ALERT: This flow has been flagged as an active Exploit. Layer 2 Random Forest returned a 98% threat probability, and Layer 3 LSTM confirmed the chronological sequence with 95% probability. Local SHAP attributions indicate that destination port and inbound bytes were the main features triggering this anomaly."
  },
  {
    type: "triage_l1",
    content: "[Triage] Benign flow dropped by L1 filter. Anomaly score: 0.31",
    title: "Layer 1 - Volumetric Filter Drop",
    explanation: "Another standard background flow dropped by the Layer 1 Volumetric filter (Anomaly score: 0.31), bypasses all heavier ML/DL execution blocks."
  },
  {
    type: "info_l3",
    content: "[Info] Flow reached L3. Classified normal. L3 Prob: 0.04",
    title: "Layer 3 - Sequential Normal Classification",
    explanation: "The flow was passed through Layer 1 and Layer 2 because it had high standalone anomalies. However, the Layer 3 PyTorch LSTM tracked the last 10 sequential events for this host and found no suspicious state transitions or beaconing pathways (threat probability: 4%). It is classified as normal."
  },
  {
    type: "alert",
    content: "[ALERT] [Threat Detected!] Type: Reconnaissance | L2 Prob: 0.94 | L3 Prob: 0.91 | Top SHAP reasons: ['src_port', 'duration']",
    title: "Layer 2 & 3 - High Fidelity Threat Alert",
    explanation: "SECURITY ALERT: Network scan / Reconnaissance activities detected. The Random Forest model detected anomalies with 94% probability, and the PyTorch LSTM validated the beaconing pattern over time with 91% probability. Source port scanning and abnormal connections duration are key triggers."
  }
];

const MATRIX_STATS = {
  rf: {
    tn: "1,892",
    fp: "10",
    fn: "1",
    tp: "3,497",
    precision: "99.71%",
    recall: "99.97%",
    f1: "99.84%"
  },
  lstm: {
    tn: "1,854",
    fp: "48",
    fn: "80",
    tp: "3,418",
    precision: "98.61%",
    recall: "97.71%",
    f1: "98.16%"
  }
};

export function Performance() {
  const { sidebarCollapsed } = useAppStore();
  const [activeTab, setActiveTab] = useState<"rf" | "lstm">("rf");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [isTerminalPaused, setIsTerminalPaused] = useState(false);

  // Initialize terminal simulation logs
  useEffect(() => {
    // Add first 3 logs immediately
    const initialLogs = SIMULATED_LOGS.slice(0, 3).map((l, index) => ({
      ...l,
      id: index,
      time: new Date().toLocaleTimeString()
    }));
    setLogs(initialLogs);
    setSelectedLog(initialLogs[2]); // select the triage log initially
  }, []);

  // Add new logs periodically to simulate real-time CLI output
  useEffect(() => {
    if (isTerminalPaused) return;

    const interval = setInterval(() => {
      setLogs((prev) => {
        const nextLogIndex = prev.length % SIMULATED_LOGS.length;
        const template = SIMULATED_LOGS[nextLogIndex];
        const newLog: LogEntry = {
          ...template,
          id: prev.length,
          time: new Date().toLocaleTimeString()
        };
        
        return [...prev.slice(-30), newLog]; // Keep last 30 logs in buffer
      });
    }, 4000);

    return () => clearInterval(interval);
  }, [isTerminalPaused]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar Nav */}
      <Sidebar />

      {/* Main Panel Content */}
      <main className={`flex-1 transition-all duration-300 p-8 ${sidebarCollapsed ? "ml-16" : "ml-64"}`}>
        
        {/* Top Header Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Model Evaluation & Simulator Logs</h1>
            <p className="text-xs text-slate-400 mt-1">
              Offline performance benchmarks, confusion matrices, and live command prompt log telemetry.
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            <a 
              href="/Model_Performance_Report.pdf" 
              download="Model_Performance_Report.pdf"
              className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium text-xs px-4 py-2.5 rounded-lg border border-indigo-500 shadow-md transition-colors"
            >
              <Download className="w-4 h-4" /> Download PDF Report
            </a>
          </div>
        </div>

        {/* 4 Summary Cards Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 mt-8">
          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">L2 RF Accuracy</CardTitle>
              <Cpu className="w-5 h-5 text-indigo-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-white">99.80%</div>
              <p className="text-xxs text-slate-500 mt-1">Supervised Random Forest classification rate.</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">L2 RF Recall</CardTitle>
              <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-emerald-400">100.0%</div>
              <p className="text-xxs text-slate-500 mt-1">Percentage of standalone attacks correctly caught.</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">L3 LSTM Accuracy</CardTitle>
              <Activity className="w-5 h-5 text-rose-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-white">97.63%</div>
              <p className="text-xxs text-slate-500 mt-1">Chronological sequence recognition accuracy.</p>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/40 border-slate-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Inference Latency</CardTitle>
              <FileText className="w-5 h-5 text-amber-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-black text-amber-400">&lt; 5 ms</div>
              <p className="text-xxs text-slate-500 mt-1">Average pipeline Layer 2 processing duration.</p>
            </CardContent>
          </Card>
        </div>

        {/* Live Simulator Log Feed Section */}
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Terminal Console Column */}
          <div className="lg:col-span-2 flex flex-col bg-slate-900/30 border border-slate-800 rounded-xl p-5 overflow-hidden">
            <div className="flex items-center justify-between pb-4">
              <div className="flex items-center gap-2">
                <TerminalIcon className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Live Pipeline Simulator CLI Output</h3>
              </div>
              <button 
                onClick={() => setIsTerminalPaused(!isTerminalPaused)}
                className={`flex items-center gap-1.5 text-xxs font-mono px-2 py-1 rounded transition-colors ${
                  isTerminalPaused 
                    ? "bg-amber-600/20 text-amber-400 hover:bg-amber-600/30" 
                    : "bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30"
                }`}
              >
                <RefreshCw className={`w-3 h-3 ${isTerminalPaused ? "" : "animate-spin"}`} />
                {isTerminalPaused ? "RESUME FEED" : "PAUSE FEED"}
              </button>
            </div>
            
            {/* Console Screen */}
            <div className="h-80 bg-black text-slate-300 font-mono text-xs p-4 rounded-lg border border-slate-950 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-800 flex flex-col gap-1.5 shadow-inner">
              {logs.map((log) => {
                let colorClass = "text-slate-400";
                if (log.type === "alert") colorClass = "text-rose-500 font-bold";
                if (log.type === "triage_l1") colorClass = "text-emerald-500";
                if (log.type === "triage_l2") colorClass = "text-orange-400";
                if (log.type === "info_l3") colorClass = "text-indigo-400";
                
                const isSelected = selectedLog?.id === log.id;

                return (
                  <div 
                    key={log.id} 
                    onClick={() => setSelectedLog(log)}
                    className={`py-1 px-2 rounded cursor-pointer transition-colors hover:bg-slate-900/50 flex items-start gap-2 ${isSelected ? "bg-slate-900 border-l-2 border-indigo-500 text-white" : ""}`}
                  >
                    <span className="text-slate-600 select-none text-xxs mt-0.5">[{log.time}]</span>
                    <span className={`break-all ${colorClass}`}>{log.content}</span>
                  </div>
                );
              })}
            </div>
            <p className="text-xxs text-slate-500 mt-2 italic">Click on any log line in the console to inspect its security interpretation panel on the right.</p>
          </div>

          {/* Explanation Tooltip Panel Column */}
          <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 flex flex-col">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider pb-4 border-b border-slate-800 flex items-center gap-1.5">
              <Info className="w-4 h-4 text-indigo-400" /> Log Inspector
            </h3>
            
            {selectedLog ? (
              <div className="flex-1 flex flex-col justify-between mt-4">
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <span className={`w-2.5 h-2.5 rounded-full ${
                      selectedLog.type === "alert" ? "bg-rose-500 animate-pulse" :
                      selectedLog.type === "triage_l1" ? "bg-emerald-500" :
                      selectedLog.type === "triage_l2" ? "bg-orange-400" : "bg-indigo-500"
                    }`} />
                    <h4 className="text-sm font-bold text-slate-100">{selectedLog.title}</h4>
                  </div>
                  
                  <div className="bg-black/40 border border-slate-950 p-3 rounded text-xxs font-mono text-slate-400 break-all leading-normal">
                    {selectedLog.content}
                  </div>

                  <div className="text-xs text-slate-400 leading-relaxed space-y-2">
                    <p className="font-semibold text-slate-300">Technical Breakdown:</p>
                    <p>{selectedLog.explanation}</p>
                  </div>
                </div>

                <div className="mt-6 border-t border-slate-800 pt-4 text-xxs text-slate-500">
                  <span>Defense Pipeline State: </span>
                  <span className="text-indigo-400 font-semibold uppercase font-mono">
                    {selectedLog.type === "triage_l1" ? "L1 Stateful Triage" :
                     selectedLog.type === "triage_l2" ? "L2 Contextual ML" :
                     selectedLog.type === "alert" ? "L3 Sequence Alert" : "System Thread"}
                  </span>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-center text-slate-500 p-6">
                <TerminalIcon className="w-8 h-8 opacity-20 mb-2" />
                <p className="text-xs">No log selected. Click any command prompt log line to view analysis.</p>
              </div>
            )}
          </div>
        </div>

        {/* Offline Evaluation & Confusion Matrices */}
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Detailed Interpretation Panel */}
          <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider pb-4">Trained Estimators Config</h3>
              <div className="space-y-4 text-xs text-slate-400 mt-2">
                <div className="border-b border-slate-800 pb-3">
                  <span className="font-semibold text-slate-300 block">Layer 2: Contextual Random Forest</span>
                  <span className="text-xxs font-mono text-indigo-400">100 Trees, Depth 12, Scikit-Learn</span>
                  <p className="mt-1 leading-normal text-xxs">Trained on 18,000 balanced OCSF entries constructed from CICIDS2017, UNSW-NB15, and CSE-CIC-IDS2018. Fitted with StandardScaler to normalize volumetric rates.</p>
                </div>

                <div className="border-b border-slate-800 pb-3">
                  <span className="font-semibold text-slate-300 block">Layer 3: Sequential PyTorch LSTM</span>
                  <span className="text-xxs font-mono text-indigo-400">2 Layers, 64 Hidden Units, PyTorch</span>
                  <p className="mt-1 leading-normal text-xxs">Statefully trained on sliding event sequences to capture chronologically sequence-order dependencies (e.g., beaconing intervals). Achieved best loss of 0.0865 at Epoch 18.</p>
                </div>

                <div>
                  <span className="font-semibold text-slate-300 block">System Latency Optimization</span>
                  <span className="text-xxs font-mono text-emerald-400">90% Bypass Rate</span>
                  <p className="mt-1 leading-normal text-xxs">Simulation metrics demonstrate that 90.0% of standard traffic drops at Layer 0/1 without running heavy ML/DL layers, leading to a 14.5% latency reduction.</p>
                </div>
              </div>
            </div>
            
            <div className="bg-slate-950/40 p-4 border border-slate-800 rounded-lg text-xxs text-slate-500 mt-6 leading-relaxed">
              <div className="flex items-center gap-1.5 text-indigo-400 font-bold mb-1">
                <Layers className="w-3.5 h-3.5" />
                <span>Sequence-Order Verification</span>
              </div>
              During validation, reversing the sequence order of a lateral movement threat signature dropped its probability from 99.42% to 0.46%, mathematically proving that the LSTM tracks sequence-order patterns, not just static flow details.
            </div>
          </div>

          {/* Confusion Matrix Tabs Panel */}
          <div className="lg:col-span-2 bg-slate-900/30 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 gap-3 border-b border-slate-800/60">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Confusion Matrices</h3>
              
              {/* Tab Selector Buttons */}
              <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800 text-xxs font-mono">
                <button
                  onClick={() => setActiveTab("rf")}
                  className={`px-3 py-1.5 rounded transition-all ${activeTab === "rf" ? "bg-indigo-600 text-white shadow" : "text-slate-400 hover:text-white"}`}
                >
                  LAYER 2 RANDOM FOREST
                </button>
                <button
                  onClick={() => setActiveTab("lstm")}
                  className={`px-3 py-1.5 rounded transition-all ${activeTab === "lstm" ? "bg-indigo-600 text-white shadow" : "text-slate-400 hover:text-white"}`}
                >
                  LAYER 3 PYTORCH LSTM
                </button>
              </div>
            </div>

            {/* Matrix Visuals & Stats */}
            <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch mt-4">
              
              {/* Left Column: Image wrapper */}
              <div className="bg-black/60 p-4 rounded-xl border border-slate-950 text-center flex flex-col items-center justify-center min-h-[300px] w-full">
                {activeTab === "rf" ? (
                  <div className="space-y-2 w-full">
                    <img 
                      src="/rf_confusion_matrix.png" 
                      alt="Random Forest Confusion Matrix" 
                      className="max-h-64 mx-auto rounded border border-slate-800 object-contain"
                    />
                    <span className="text-xxs text-slate-500 font-mono block italic">Figure A: Contextual RF Confusion Matrix</span>
                  </div>
                ) : (
                  <div className="space-y-2 w-full">
                    <img 
                      src="/lstm_confusion_matrix.png" 
                      alt="PyTorch LSTM Confusion Matrix" 
                      className="max-h-64 mx-auto rounded border border-slate-800 object-contain"
                    />
                    <span className="text-xxs text-slate-500 font-mono block italic">Figure B: PyTorch LSTM Confusion Matrix</span>
                  </div>
                )}
              </div>

              {/* Right Column: Quantitative Highlights */}
              <div className="flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center gap-1.5 text-slate-200 font-bold uppercase tracking-wider text-xxs mb-3">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                    <span>Model Stats & Corporate Interpretation</span>
                  </div>

                  {/* Model Metrics Pills */}
                  <div className="flex flex-wrap gap-2 mb-4">
                    <div className="bg-indigo-950/40 border border-indigo-800/60 px-2.5 py-1 rounded-full text-xxs font-semibold text-indigo-300">
                      Precision: {MATRIX_STATS[activeTab].precision}
                    </div>
                    <div className="bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded-full text-xxs font-semibold text-emerald-300">
                      Recall: {MATRIX_STATS[activeTab].recall}
                    </div>
                    <div className="bg-purple-950/40 border border-purple-800/60 px-2.5 py-1 rounded-full text-xxs font-semibold text-purple-300">
                      F1-Score: {MATRIX_STATS[activeTab].f1}
                    </div>
                  </div>

                  {/* 2x2 Matrix Grid */}
                  <div className="grid grid-cols-2 gap-3 mb-4">
                    {/* True Negatives */}
                    <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-semibold">True Negatives (TN)</div>
                      <div className="text-base font-black text-emerald-400 font-mono mt-0.5">{MATRIX_STATS[activeTab].tn}</div>
                      <div className="text-[9px] text-slate-500 leading-tight mt-0.5">Benign traffic passed</div>
                    </div>
                    {/* False Positives */}
                    <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-semibold">False Positives (FP)</div>
                      <div className="text-base font-black text-amber-500 font-mono mt-0.5">{MATRIX_STATS[activeTab].fp}</div>
                      <div className="text-[9px] text-slate-500 leading-tight mt-0.5">Safe traffic flagged</div>
                    </div>
                    {/* False Negatives */}
                    <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-semibold">False Negatives (FN)</div>
                      <div className="text-base font-black text-rose-500 font-mono mt-0.5">{MATRIX_STATS[activeTab].fn}</div>
                      <div className="text-[9px] text-slate-500 leading-tight mt-0.5">Threats missed</div>
                    </div>
                    {/* True Positives */}
                    <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/80">
                      <div className="text-[10px] text-slate-500 uppercase font-semibold">True Positives (TP)</div>
                      <div className="text-base font-black text-emerald-400 font-mono mt-0.5">{MATRIX_STATS[activeTab].tp}</div>
                      <div className="text-[9px] text-slate-500 leading-tight mt-0.5">Threats identified</div>
                    </div>
                  </div>
                </div>

                {activeTab === "rf" ? (
                  <div className="text-xxs leading-relaxed text-slate-400 bg-slate-950/30 p-3 rounded-lg border border-slate-900">
                    <p>
                      <strong>Random Forest Performance:</strong> Achieved near-perfect classification. 
                      A extremely low False Positive rate (<strong className="text-rose-400">0.5%</strong>) prevents SOC alert fatigue, 
                      while a <strong className="text-indigo-400">99.97%</strong> recall restricts undetected malicious penetration to near-zero.
                    </p>
                  </div>
                ) : (
                  <div className="text-xxs leading-relaxed text-slate-400 bg-slate-950/30 p-3 rounded-lg border border-slate-900">
                    <p>
                      <strong>LSTM Sequence Performance:</strong> Maps chronological event sequences statefully. 
                      This prevents slow beaconing activities (APT lateral movements) from going undetected 
                      even if each individual flow seems benign when evaluated in isolation.
                    </p>
                  </div>
                )}
              </div>

            </div>

          </div>

        </div>

      </main>
    </div>
  );
}
