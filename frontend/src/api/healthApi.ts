import { axiosInstance } from "./axiosInstance";
import { mockHealthStatus, HealthStatus } from "../mocks/metricsMock";

export const fetchHealthStatus = async (): Promise<HealthStatus> => {
  try {
    const response = await axiosInstance.get<HealthStatus>("/api/v1/health");
    return response.data;
  } catch (error) {
    console.warn("Backend health endpoint unreachable, falling back to mock health data.", error);
    return mockHealthStatus;
  }
};
