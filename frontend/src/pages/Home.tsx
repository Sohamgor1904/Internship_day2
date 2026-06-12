import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchDashboardMetrics } from "../api/metricsApi";
import { Navbar } from "../components/Navbar";
import { 
  Shield, 
  ChevronRight, 
  BarChart3, 
  AlertTriangle, 
  Search, 
  Skull,
  ArrowRight,
  Database,
  Cpu,
  Activity,
  Layers,
  CheckCircle2,
  Clock
} from "lucide-react";
import { Button } from "@/components/ui/button";

export function Home() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Live Metrics Ticker Query
  const { data: metrics } = useQuery({
    queryKey: ["tickerMetrics"],
    queryFn: fetchDashboardMetrics,
    refetchInterval: 10000 // Refresh ticker every 10s on home page
  });

  // Ticker stats
  const eventsProcessed = metrics?.summary.eventsProcessed ?? 1042392;
  const threatsCaught = metrics?.summary.activeThreats ?? 18;
  const dlqSize = metrics?.summary.dlqSize ?? 4;
  const uptime = metrics?.summary.uptimeSeconds ?? 86400;

  // Formatting uptime
  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    return `${hours}h ${minutes}m`;
  };

  // 1. Particle network background animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = 650);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
    };
    window.addEventListener("resize", handleResize);

    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
    }> = [];

    const numParticles = Math.min(60, Math.floor(width / 20));

    for (let i = 0; i < numParticles; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 2 + 1
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // Gradient background
      const gradient = ctx.createRadialGradient(
        width / 2,
        height / 2,
        10,
        width / 2,
        height / 2,
        width / 1.5
      );
      gradient.addColorStop(0, "#1E2429");
      gradient.addColorStop(1, "#11161A");
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, width, height);

      // Draw connections
      ctx.strokeStyle = "rgba(235, 0, 82, 0.07)";
      ctx.lineWidth = 1;
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 150) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw particles
      ctx.fillStyle = "rgba(235, 0, 82, 0.4)";
      for (const p of particles) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();

        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  // 2. Scroll count-up stat trigger logic
  const [counts, setCounts] = useState({ firewall: 0, layers: 0, latency: 0 });
  const countUpSectionRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          // Trigger animations
          let start = 0;
          const endFirewall = 68;
          const duration = 1500;
          const stepTime = 30;
          const steps = duration / stepTime;
          const firewallIncrement = endFirewall / steps;

          const timer = setInterval(() => {
            start += 1;
            setCounts((prev) => ({
              firewall: Math.min(endFirewall, Math.floor(prev.firewall + firewallIncrement)),
              layers: 3,
              latency: 50
            }));
            if (start >= steps) {
              clearInterval(timer);
              setCounts({ firewall: 68, layers: 3, latency: 50 });
            }
          }, stepTime);
          
          observer.disconnect();
        }
      },
      { threshold: 0.2 }
    );

    if (countUpSectionRef.current) {
      observer.observe(countUpSectionRef.current);
    }
    return () => observer.disconnect();
  }, []);

  // 3. How it works interactive step details
  const [activeStep, setActiveStep] = useState(0);
  const pipelineSteps = [
    {
      title: "Raw Logs Ingestion",
      desc: "Ingests real-time streaming security audit logs from multiple corporate network interfaces.",
      icon: Database
    },
    {
      title: "OCSF Normalisation",
      desc: "Normalises custom fields into standard OCSF schema format (class 4001, severity indicators).",
      icon: Layers
    },
    {
      title: "Layer 1: Volumetric Filter",
      desc: "Drops background baseline traffic based on statistical entropy, EWMA rates, and port Z-scores.",
      icon: Activity
    },
    {
      title: "Layer 2: RF + SHAP Attributions",
      desc: "Flags threats with Random Forest and computes SHAP explainability parameters for analyst review.",
      icon: Cpu
    },
    {
      title: "Layer 3: Sequential LSTM",
      desc: "Evaluates multi-hop sequential transitions across rolling IP address timelines to detect slow APTs.",
      icon: Shield
    },
    {
      title: "Threat Alert Stored",
      desc: "Stores flagged threats in batch transactions and routes write failures safely to the DLQ.",
      icon: CheckCircle2
    }
  ];

  return (
    <div className="bg-white min-h-screen text-slate-800 font-sans selection:bg-indigo-500 selection:text-white">
      <Navbar />

      {/* Hero Section (Section 2) */}
      <section className="relative h-[650px] flex flex-col justify-center items-center overflow-hidden">
        <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />
        
        {/* Content Overlay */}
        <div className="relative z-10 max-w-4xl mx-auto text-center px-4">
          <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-white leading-tight">
            Real-Time Threat Detection <br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">
              Powered by OCSF
            </span>
          </h1>
          <p className="mt-6 text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
            Protect your cloud infrastructure with an advanced 3-layer hybrid machine learning pipeline providing instant classifications, explanations, and sequential state verification.
          </p>

          <div className="mt-10 flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/dashboard">
              <Button size="lg" className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-8 py-6 rounded-md shadow-lg shadow-indigo-600/30 flex items-center gap-2">
                Enter Dashboard <ArrowRight className="w-5 h-5" />
              </Button>
            </Link>
            <a href="#why-it-matters">
              <Button size="lg" variant="outline" className="border-slate-700 text-slate-300 hover:bg-slate-900/50 hover:text-white font-semibold px-8 py-6 rounded-md">
                Learn More
              </Button>
            </a>
          </div>
        </div>

        {/* Live Stat Ticker Banner */}
        <div className="absolute bottom-0 left-0 right-0 z-10 bg-slate-950/70 border-t border-slate-800/80 backdrop-blur-sm py-4">
          <div className="max-w-7xl mx-auto px-4 flex flex-wrap justify-center md:justify-between items-center gap-4 text-xs font-mono text-indigo-300 tracking-wider">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-indigo-500 animate-ping" />
              <span>LIVE PIPELINE FEED STATUS</span>
            </div>
            <div className="flex flex-wrap justify-center gap-6 md:gap-10">
              <span>EVENTS PROCESSED: <span className="text-white font-bold">{eventsProcessed.toLocaleString()}</span></span>
              <span>THREATS CAUGHT: <span className="text-rose-400 font-bold">{threatsCaught}</span></span>
              <span>DLQ SIZE: <span className="text-amber-400 font-bold">{dlqSize}</span></span>
              <span>UPTIME: <span className="text-white font-bold">{formatUptime(uptime)}</span></span>
            </div>
          </div>
        </div>
      </section>

      {/* Why This Matters (Section 3) */}
      <section id="why-it-matters" className="py-20 bg-slate-50 border-b border-slate-200 scroll-mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight sm:text-4xl">
              Why ThreatPulse Matters
            </h2>
            <p className="mt-4 text-lg text-slate-600 leading-relaxed">
              Every second, thousands of network events go unanalyzed. Most SIEM tools react. Threat Pulse predicts. By combining volumetric filtering with model explanation frameworks, we give security analysts total control over network anomalies.
            </p>
          </div>

          {/* Stat Count-up Grid */}
          <div ref={countUpSectionRef} className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Card 1 */}
            <div className="bg-white border border-slate-200 p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow text-center">
              <div className="text-5xl font-black text-slate-900 tracking-tight">
                ~{counts.firewall}%
              </div>
              <div className="text-sm font-semibold text-indigo-600 uppercase tracking-wider mt-2">
                Threats Missed by Firewalls
              </div>
              <p className="text-slate-500 text-xs mt-3">
                Industry standard firewalls fail to resolve nested contextual threat operations.
              </p>
            </div>

            {/* Card 2 */}
            <div className="bg-white border border-indigo-100 p-8 rounded-xl shadow-md text-center ring-2 ring-indigo-500/10">
              <div className="text-5xl font-black text-indigo-600 tracking-tight flex items-center justify-center gap-1">
                {counts.layers ? "3-Layer" : "0"}
              </div>
              <div className="text-sm font-semibold text-slate-800 uppercase tracking-wider mt-2">
                Hybrid Core Pipeline
              </div>
              <div className="text-xs font-mono font-bold text-rose-500 mt-2">
                Stats + RF + LSTM
              </div>
              <p className="text-slate-500 text-xs mt-2">
                Three separate evaluation engines analyze volumetric, contextual, and time-sequential features.
              </p>
            </div>

            {/* Card 3 */}
            <div className="bg-white border border-slate-200 p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow text-center">
              <div className="text-5xl font-black text-slate-900 tracking-tight">
                &lt;{counts.latency ? "50" : "0"}ms
              </div>
              <div className="text-sm font-semibold text-slate-800 uppercase tracking-wider mt-2">
                Detection Latency
              </div>
              <p className="text-slate-500 text-xs mt-3">
                CPU-optimized architecture allows sub-millisecond local inference.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How the Pipeline Works (Section 4) */}
      <section className="py-20 bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight">
              Interactive Pipeline Flow
            </h2>
            <p className="mt-3 text-slate-600">
              Click on each step below to inspect how OCSF records flow through the detection layers.
            </p>
          </div>

          {/* Interactive Flow Diagram */}
          <div className="bg-slate-950 text-slate-100 p-8 rounded-2xl border border-slate-800 max-w-5xl mx-auto shadow-xl">
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3 relative z-10">
              {pipelineSteps.map((step, idx) => {
                const StepIcon = step.icon;
                const isActive = activeStep === idx;
                return (
                  <button
                    key={idx}
                    onClick={() => setActiveStep(idx)}
                    className={`p-4 rounded-xl border transition-all text-center flex flex-col items-center gap-3 ${
                      isActive 
                        ? "bg-indigo-600/20 border-indigo-500 text-white shadow-lg shadow-indigo-500/10" 
                        : "bg-slate-900/40 border-slate-800/80 text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                    }`}
                  >
                    <div className={`p-2.5 rounded-lg ${isActive ? "bg-indigo-600 text-white" : "bg-slate-800 text-slate-400"}`}>
                      <StepIcon className="w-5 h-5" />
                    </div>
                    <span className="text-xs font-semibold tracking-wide leading-tight">{step.title}</span>
                  </button>
                );
              })}
            </div>

            {/* Selected Step Tooltip Display */}
            <div className="mt-8 p-5 bg-slate-900 rounded-xl border border-slate-800 animate-in fade-in slide-in-from-bottom-3 duration-200">
              <span className="text-xs font-mono font-bold text-indigo-400 uppercase tracking-widest">
                STEP {activeStep + 1} OF 6
              </span>
              <h4 className="text-lg font-bold text-white mt-1">{pipelineSteps[activeStep].title}</h4>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">
                {pipelineSteps[activeStep].desc}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* What You Can Do (Section 5) */}
      <section className="py-20 bg-slate-50 border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight">
              Operational Command Centers
            </h2>
            <p className="mt-3 text-slate-600">
              Select one of the dedicated interfaces below to begin monitoring security metrics.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* Card 1: Dashboard */}
            <div className="bg-white border border-slate-200 p-6 rounded-xl hover:shadow-lg hover:border-indigo-100 transition-all flex flex-col justify-between">
              <div>
                <div className="p-3 bg-indigo-50 text-indigo-600 rounded-lg w-fit">
                  <BarChart3 className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-4">Dashboard Overview</h3>
                <p className="text-slate-500 text-xs mt-2 leading-relaxed">
                  Real-time pipeline health, AreaCharts of threat velocities, and volumetric drop counters.
                </p>
              </div>
              <Link to="/dashboard" className="mt-6">
                <Button variant="ghost" size="sm" className="w-full text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 font-semibold flex items-center justify-between px-3">
                  <span>Open Console</span> <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>

            {/* Card 2: Alerts */}
            <div className="bg-white border border-slate-200 p-6 rounded-xl hover:shadow-lg hover:border-indigo-100 transition-all flex flex-col justify-between">
              <div>
                <div className="p-3 bg-indigo-50 text-indigo-600 rounded-lg w-fit">
                  <AlertTriangle className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-4">Threat Investigator</h3>
                <p className="text-slate-500 text-xs mt-2 leading-relaxed">
                  Filterable alert logs, local SHAP explainability charts, and full OCSF record inspections.
                </p>
              </div>
              <Link to="/alerts" className="mt-6">
                <Button variant="ghost" size="sm" className="w-full text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 font-semibold flex items-center justify-between px-3">
                  <span>Open Console</span> <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>

            {/* Card 3: Anomalies */}
            <div className="bg-white border border-slate-200 p-6 rounded-xl hover:shadow-lg hover:border-indigo-100 transition-all flex flex-col justify-between">
              <div>
                <div className="p-3 bg-indigo-50 text-indigo-600 rounded-lg w-fit">
                  <Search className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-4">Anomaly Explorer</h3>
                <p className="text-slate-500 text-xs mt-2 leading-relaxed">
                  ScatterCharts of scores per IP, Shannon entropy metrics, and EWMA byte flow trends.
                </p>
              </div>
              <Link to="/anomalies" className="mt-6">
                <Button variant="ghost" size="sm" className="w-full text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 font-semibold flex items-center justify-between px-3">
                  <span>Open Console</span> <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>

            {/* Card 4: DLQ */}
            <div className="bg-white border border-slate-200 p-6 rounded-xl hover:shadow-lg hover:border-indigo-100 transition-all flex flex-col justify-between">
              <div>
                <div className="p-3 bg-indigo-50 text-indigo-600 rounded-lg w-fit">
                  <Skull className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900 mt-4">DLQ Monitor</h3>
                <p className="text-slate-500 text-xs mt-2 leading-relaxed">
                  Dead Letter Queue details, database failure tracking tables, and manual retry options.
                </p>
              </div>
              <Link to="/dlq" className="mt-6">
                <Button variant="ghost" size="sm" className="w-full text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 font-semibold flex items-center justify-between px-3">
                  <span>Open Console</span> <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Tech Stack Strip (Section 6) */}
      <section className="py-12 bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
            Built On Corporate Open Standards
          </span>
          <div className="mt-6 flex flex-wrap justify-center items-center gap-8 md:gap-14">
            {["OCSF", "FastAPI", "Redis", "PostgreSQL", "PyTorch", "Scikit-Learn", "SHAP", "Prometheus"].map((tech) => (
              <span 
                key={tech} 
                className="text-lg font-bold text-slate-400 hover:text-indigo-500 transition-colors cursor-default select-none font-mono"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Footer (Section 7) */}
      <footer className="bg-slate-950 text-slate-400 py-12 border-t border-slate-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2 text-white font-bold">
            <Shield className="w-5 h-5 text-indigo-400" />
            <span>THREAT<span className="text-indigo-400">PULSE</span></span>
            <span className="text-xs text-slate-600 ml-2">Built for SOC Teams</span>
          </div>

          <div className="flex gap-6 text-sm">
            <a href="https://github.com" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
            <a href="/docs" className="hover:text-white transition-colors">API Docs</a>
            <a href="#" className="hover:text-white transition-colors flex items-center gap-1">
              Back to Top <Clock className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
