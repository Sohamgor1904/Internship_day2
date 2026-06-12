import { axiosInstance } from "./axiosInstance";
import { mockAlerts, AlertObject } from "../mocks/alertsMock";

export const fetchAlerts = async (): Promise<AlertObject[]> => {
  try {
    const response = await axiosInstance.get<AlertObject[]>("/api/v1/alerts");
    return response.data;
  } catch (error) {
    console.warn("Backend alerts list unreachable, falling back to mock alerts.", error);
    return mockAlerts;
  }
};

export const detectThreat = async (record: any): Promise<any> => {
  try {
    const response = await axiosInstance.post("/api/v1/detect", record);
    return response.data;
  } catch (error) {
    console.warn("Backend detect endpoint failed, simulating mock classification.", error);
    // Simulate a mock response based on inputs
    const isAnomaly = Math.random() > 0.5;
    return {
      threat_detected: isAnomaly,
      classification: isAnomaly ? "Threat-Activity" : "Benign",
      layer_reached: isAnomaly ? 2 : 1,
      layer1: { passed_triage: true, anomaly_score: 3.4 },
      layer2: { prediction: isAnomaly ? 1 : 0, threat_probability: isAnomaly ? 0.82 : 0.08, explanations: [] },
      layer3: { threat_probability: 0.05 }
    };
  }
};
