export interface HealthStatus {
  status: "healthy" | "degraded";
  components: {
    database: "healthy" | "unhealthy";
    pipeline: "healthy" | "unhealthy";
    redis: "healthy" | "unhealthy";
  };
}

export interface SummaryMetrics {
  totalAlertsToday: number;
  activeThreats: number;
  dlqSize: number;
  eventsProcessed: number;
  uptimeSeconds: number;
}

export interface TimelineDataPoint {
  time: string; // MM:SS or HH:MM
  alertsCount: number;
  trafficRate: number;
}

export interface VolumetricDataPoint {
  layer: string;
  count: number;
  color: string;
}

export const mockHealthStatus: HealthStatus = {
  status: "healthy",
  components: {
    database: "healthy",
    pipeline: "healthy",
    redis: "healthy"
  }
};

export const mockSummaryMetrics: SummaryMetrics = {
  totalAlertsToday: 142,
  activeThreats: 18,
  dlqSize: 4,
  eventsProcessed: 1042392,
  uptimeSeconds: 86400 // 24 hours
};

// Generate last 60 minutes timeline mock data
export const generateTimelineMetrics = (): TimelineDataPoint[] => {
  const data: TimelineDataPoint[] = [];
  const baseTime = new Date();
  
  for (let i = 59; i >= 0; i--) {
    const timePoint = new Date(baseTime.getTime() - i * 60 * 1000);
    const mm = String(timePoint.getMinutes()).padStart(2, "0");
    const hh = String(timePoint.getHours()).padStart(2, "0");
    
    // Create alert volumes with random perturbations for visual dynamism
    const baseAlerts = Math.floor(Math.sin(i / 5) * 5) + 8;
    const randomVariation = Math.floor(Math.random() * 4) - 2;
    
    data.push({
      time: `${hh}:${mm}`,
      alertsCount: Math.max(0, baseAlerts + randomVariation),
      trafficRate: Math.floor(Math.random() * 1000) + 4000
    });
  }
  return data;
};

export const mockTimelineMetrics = generateTimelineMetrics();

export const mockVolumetricMetrics: VolumetricDataPoint[] = [
  { layer: "Layer 1 (Dropped)", count: 893204, color: "#eab308" },
  { layer: "Layer 2 (Flagged)", count: 182, color: "#f97316" },
  { layer: "Layer 3 (Confirmed)", count: 18, color: "#ef4444" }
];

export const mockPrometheusText = `
# HELP threat_detector_processed_events_total Total number of security events processed.
# TYPE threat_detector_processed_events_total counter
threat_detector_processed_events_total{layer="1",decision="dropped"} 893204
threat_detector_processed_events_total{layer="2",decision="dropped"} 149020
threat_detector_processed_events_total{layer="3",decision="benign"} 86
threat_detector_processed_events_total{layer="3",decision="threat"} 18
# HELP threat_detector_inference_latency_seconds_sum Sum of ML models execution durations.
# TYPE threat_detector_inference_latency_seconds_sum gauge
threat_detector_inference_latency_seconds_sum{model="rf"} 2.45
threat_detector_inference_latency_seconds_sum{model="shap"} 15.68
threat_detector_inference_latency_seconds_sum{model="lstm"} 8.92
# HELP threat_detector_inference_latency_seconds_count Count of ML model inferences.
# TYPE threat_detector_inference_latency_seconds_count gauge
threat_detector_inference_latency_seconds_count{model="rf"} 182
threat_detector_inference_latency_seconds_count{model="shap"} 18
threat_detector_inference_latency_seconds_count{model="lstm"} 18
# HELP threat_detector_database_batch_queue_size Buffered DB alerts queue size.
# TYPE threat_detector_database_batch_queue_size gauge
threat_detector_database_batch_queue_size 4
# HELP threat_detector_database_healthy Operational database connection check.
# TYPE threat_detector_database_healthy gauge
threat_detector_database_healthy 1
`;
