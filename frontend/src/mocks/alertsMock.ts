export interface ShapExplanation {
  feature_name: string;
  shap_value: number;
}

export interface AlertObject {
  id: number;
  timestamp: string; // ISO string for presentation
  time_epoch: number; // millisecond timestamp
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  bytes_in: number;
  bytes_out: number;
  l1_anomaly_score: number;
  l2_threat_prob: number;
  l3_threat_prob: number;
  classification: "Threat-Activity" | "Threat-Anomaly" | "Threat-Sequential-APT" | "Benign";
  is_anomaly: boolean;
  explanations: ShapExplanation[];
  model_version: string;
}

export const mockAlerts: AlertObject[] = [
  {
    id: 1,
    timestamp: "2026-06-11T11:00:00.000Z",
    time_epoch: 1781262000000,
    src_ip: "192.168.1.105",
    src_port: 52001,
    dst_ip: "10.0.0.1",
    dst_port: 22,
    protocol: "tcp",
    bytes_in: 45,
    bytes_out: 48000,
    l1_anomaly_score: 4.8,
    l2_threat_prob: 0.94,
    l3_threat_prob: 0.35,
    classification: "Threat-Activity",
    is_anomaly: true,
    explanations: [
      { feature_name: "bytes_out", shap_value: 0.38 },
      { feature_name: "delta_t", shap_value: 0.22 },
      { feature_name: "packets_rate", shap_value: 0.15 },
      { feature_name: "dst_port_entropy", shap_value: -0.05 },
      { feature_name: "flow_duration", shap_value: 0.08 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 2,
    timestamp: "2026-06-11T11:05:00.000Z",
    time_epoch: 1781262300000,
    src_ip: "10.0.2.15",
    src_port: 48932,
    dst_ip: "8.8.8.8",
    dst_port: 53,
    protocol: "udp",
    bytes_in: 120000,
    bytes_out: 1400,
    l1_anomaly_score: 5.2,
    l2_threat_prob: 0.88,
    l3_threat_prob: 0.12,
    classification: "Threat-Anomaly",
    is_anomaly: true,
    explanations: [
      { feature_name: "bytes_in", shap_value: 0.45 },
      { feature_name: "byte_ratio", shap_value: 0.25 },
      { feature_name: "flow_duration", shap_value: -0.12 },
      { feature_name: "protocol_num", shap_value: 0.08 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 3,
    timestamp: "2026-06-11T11:10:00.000Z",
    time_epoch: 1781262600000,
    src_ip: "192.168.1.180",
    src_port: 4444,
    dst_ip: "172.16.0.4",
    dst_port: 443,
    protocol: "tcp",
    bytes_in: 850,
    bytes_out: 920,
    l1_anomaly_score: 2.8,
    l2_threat_prob: 0.72,
    l3_threat_prob: 0.96,
    classification: "Threat-Sequential-APT",
    is_anomaly: true,
    explanations: [
      { feature_name: "flag_switches", shap_value: 0.48 },
      { feature_name: "delta_t", shap_value: 0.32 },
      { feature_name: "dst_ip_entropy", shap_value: -0.15 },
      { feature_name: "flow_duration", shap_value: 0.12 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 4,
    timestamp: "2026-06-11T11:12:30.000Z",
    time_epoch: 1781262750000,
    src_ip: "192.168.1.105",
    src_port: 52002,
    dst_ip: "10.0.0.1",
    dst_port: 22,
    protocol: "tcp",
    bytes_in: 45,
    bytes_out: 52000,
    l1_anomaly_score: 4.9,
    l2_threat_prob: 0.95,
    l3_threat_prob: 0.42,
    classification: "Threat-Activity",
    is_anomaly: true,
    explanations: [
      { feature_name: "bytes_out", shap_value: 0.41 },
      { feature_name: "delta_t", shap_value: 0.24 },
      { feature_name: "packets_rate", shap_value: 0.16 },
      { feature_name: "dst_port_entropy", shap_value: -0.05 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 5,
    timestamp: "2026-06-11T11:15:00.000Z",
    time_epoch: 1781262900000,
    src_ip: "172.16.10.22",
    src_port: 59321,
    dst_ip: "192.168.100.4",
    dst_port: 445,
    protocol: "tcp",
    bytes_in: 84000,
    bytes_out: 920000,
    l1_anomaly_score: 3.5,
    l2_threat_prob: 0.82,
    l3_threat_prob: 0.65,
    classification: "Threat-Activity",
    is_anomaly: true,
    explanations: [
      { feature_name: "bytes_out", shap_value: 0.34 },
      { feature_name: "packets_out", shap_value: 0.28 },
      { feature_name: "dst_port_entropy", shap_value: 0.12 },
      { feature_name: "byte_ratio", shap_value: 0.11 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 6,
    timestamp: "2026-06-11T11:18:00.000Z",
    time_epoch: 1781263080000,
    src_ip: "192.168.1.180",
    src_port: 4444,
    dst_ip: "172.16.0.4",
    dst_port: 443,
    protocol: "tcp",
    bytes_in: 720,
    bytes_out: 880,
    l1_anomaly_score: 2.9,
    l2_threat_prob: 0.74,
    l3_threat_prob: 0.97,
    classification: "Threat-Sequential-APT",
    is_anomaly: true,
    explanations: [
      { feature_name: "flag_switches", shap_value: 0.51 },
      { feature_name: "delta_t", shap_value: 0.35 },
      { feature_name: "flow_duration", shap_value: 0.14 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 7,
    timestamp: "2026-06-11T11:20:00.000Z",
    time_epoch: 1781263200000,
    src_ip: "10.0.4.50",
    src_port: 38430,
    dst_ip: "10.0.0.1",
    dst_port: 80,
    protocol: "tcp",
    bytes_in: 1500,
    bytes_out: 2500,
    l1_anomaly_score: 1.1,
    l2_threat_prob: 0.05,
    l3_threat_prob: 0.02,
    classification: "Benign",
    is_anomaly: false,
    explanations: [
      { feature_name: "flow_duration", shap_value: -0.25 },
      { feature_name: "delta_t", shap_value: -0.15 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 8,
    timestamp: "2026-06-11T11:22:15.000Z",
    time_epoch: 1781263335000,
    src_ip: "192.168.1.105",
    src_port: 52003,
    dst_ip: "10.0.0.1",
    dst_port: 22,
    protocol: "tcp",
    bytes_in: 45,
    bytes_out: 49000,
    l1_anomaly_score: 4.8,
    l2_threat_prob: 0.96,
    l3_threat_prob: 0.49,
    classification: "Threat-Activity",
    is_anomaly: true,
    explanations: [
      { feature_name: "bytes_out", shap_value: 0.39 },
      { feature_name: "delta_t", shap_value: 0.23 },
      { feature_name: "packets_rate", shap_value: 0.15 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 9,
    timestamp: "2026-06-11T11:24:00.000Z",
    time_epoch: 1781263440000,
    src_ip: "192.168.1.180",
    src_port: 4444,
    dst_ip: "172.16.0.4",
    dst_port: 443,
    protocol: "tcp",
    bytes_in: 900,
    bytes_out: 940,
    l1_anomaly_score: 2.7,
    l2_threat_prob: 0.71,
    l3_threat_prob: 0.98,
    classification: "Threat-Sequential-APT",
    is_anomaly: true,
    explanations: [
      { feature_name: "flag_switches", shap_value: 0.49 },
      { feature_name: "delta_t", shap_value: 0.33 },
      { feature_name: "flow_duration", shap_value: 0.11 }
    ],
    model_version: "1.1.0"
  },
  {
    id: 10,
    timestamp: "2026-06-11T11:26:00.000Z",
    time_epoch: 1781263560000,
    src_ip: "192.168.1.25",
    src_port: 53210,
    dst_ip: "10.0.0.100",
    dst_port: 80,
    protocol: "tcp",
    bytes_in: 240,
    bytes_out: 350,
    l1_anomaly_score: 1.5,
    l2_threat_prob: 0.12,
    l3_threat_prob: 0.08,
    classification: "Benign",
    is_anomaly: false,
    explanations: [
      { feature_name: "flow_duration", shap_value: -0.18 },
      { feature_name: "delta_t", shap_value: -0.11 }
    ],
    model_version: "1.1.0"
  }
];
