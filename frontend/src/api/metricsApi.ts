import { axiosInstance } from "./axiosInstance";
import { 
  mockSummaryMetrics, 
  generateTimelineMetrics, 
  mockVolumetricMetrics, 
  mockPrometheusText,
  SummaryMetrics, 
  TimelineDataPoint, 
  VolumetricDataPoint 
} from "../mocks/metricsMock";

export interface ParsedMetrics {
  summary: SummaryMetrics;
  timeline: TimelineDataPoint[];
  volumetric: VolumetricDataPoint[];
  prometheus: {
    l1Dropped: number;
    l2Flagged: number;
    l3Confirmed: number;
    queueSize: number;
    dbHealthy: boolean;
  };
}

// Simple parser for Prometheus metrics format
const parsePrometheusMetrics = (text: string) => {
  const metrics = {
    l1Dropped: 893204,
    l2Flagged: 182,
    l3Confirmed: 18,
    queueSize: 4,
    dbHealthy: true
  };

  try {
    const lines = text.split("\n");
    for (const line of lines) {
      if (line.startsWith("#") || !line.trim()) continue;
      
      if (line.includes('threat_detector_processed_events_total{layer="1",decision="dropped"}')) {
        const val = parseInt(line.split(" ").pop() || "0", 10);
        metrics.l1Dropped = val;
      } else if (line.includes('threat_detector_processed_events_total{layer="2",decision="dropped"}')) {
        const val = parseInt(line.split(" ").pop() || "0", 10);
        // Flagged at Layer 2 means those that weren't dropped at Layer 1
        metrics.l2Flagged = val;
      } else if (line.includes('threat_detector_processed_events_total{layer="3",decision="threat"}')) {
        const val = parseInt(line.split(" ").pop() || "0", 10);
        metrics.l3Confirmed = val;
      } else if (line.includes("threat_detector_database_batch_queue_size")) {
        const val = parseInt(line.split(" ").pop() || "0", 10);
        metrics.queueSize = val;
      } else if (line.includes("threat_detector_database_healthy")) {
        const val = parseInt(line.split(" ").pop() || "1", 10);
        metrics.dbHealthy = val === 1;
      }
    }
  } catch (e) {
    console.error("Failed to parse prometheus metrics text", e);
  }

  return metrics;
};

export const fetchDashboardMetrics = async (): Promise<ParsedMetrics> => {
  let promText = mockPrometheusText;
  let summary = mockSummaryMetrics;
  
  try {
    const response = await axiosInstance.get<string>("/metrics", { responseType: "text" });
    promText = response.data;
  } catch (error) {
    console.warn("Backend metrics endpoint unreachable, using mock prometheus text.", error);
  }

  const parsedProm = parsePrometheusMetrics(promText);
  
  // Try to fetch summary stats if the endpoint is somehow active, else construct from mock/prometheus
  try {
    const response = await axiosInstance.get<any>("/api/v1/stats/summary");
    summary = {
      totalAlertsToday: response.data.total_alerts || 0,
      activeThreats: response.data.l3_alerts || 0,
      dlqSize: parsedProm.queueSize,
      eventsProcessed: response.data.total_processed || 0,
      uptimeSeconds: response.data.uptime_seconds || 86400
    };
  } catch (e) {
    summary = {
      ...mockSummaryMetrics,
      dlqSize: parsedProm.queueSize,
      activeThreats: parsedProm.l3Confirmed
    };
  }

  // Construct volumetric data dynamically
  const volumetric: VolumetricDataPoint[] = [
    { layer: "Layer 1 (Dropped)", count: parsedProm.l1Dropped, color: "#eab308" },
    { layer: "Layer 2 (Flagged)", count: parsedProm.l2Flagged, color: "#f97316" },
    { layer: "Layer 3 (Confirmed)", count: parsedProm.l3Confirmed, color: "#ef4444" }
  ];

  return {
    summary,
    timeline: generateTimelineMetrics(),
    volumetric,
    prometheus: parsedProm
  };
};
