export interface DlqItem {
  id: number;
  retryCount: number;
  firstFailedAt: string;
  lastFailedAt: string;
  failureReason: string;
  alertPayload: any;
}

export const mockDlqItems: DlqItem[] = [
  {
    id: 1,
    retryCount: 1,
    firstFailedAt: "2026-06-11T10:45:12.000Z",
    lastFailedAt: "2026-06-11T10:45:12.000Z",
    failureReason: "FATAL: connection pool timeout (60s) reached while acquiring PostgreSQL transaction connection.",
    alertPayload: {
      time_epoch: 1781261112000,
      src_ip: "192.168.1.110",
      src_port: 49301,
      dst_ip: "10.0.0.1",
      dst_port: 80,
      protocol: "tcp",
      bytes_in: 320,
      bytes_out: 480
    }
  },
  {
    id: 2,
    retryCount: 2,
    firstFailedAt: "2026-06-11T10:50:00.000Z",
    lastFailedAt: "2026-06-11T10:52:30.000Z",
    failureReason: "ERROR: deadlock detected while writing sequential host tracking indexes to the threat_alerts table.",
    alertPayload: {
      time_epoch: 1781261400000,
      src_ip: "10.0.2.15",
      src_port: 48944,
      dst_ip: "8.8.4.4",
      dst_port: 53,
      protocol: "udp",
      bytes_in: 920,
      bytes_out: 64
    }
  },
  {
    id: 3,
    retryCount: 1,
    firstFailedAt: "2026-06-11T11:02:15.000Z",
    lastFailedAt: "2026-06-11T11:02:15.000Z",
    failureReason: "ERROR: unique constraint 'threat_alerts_pkey' violated. Collision on timestamp tracking identity keys.",
    alertPayload: {
      time_epoch: 1781262135000,
      src_ip: "192.168.1.105",
      src_port: 52000,
      dst_ip: "10.0.0.1",
      dst_port: 22,
      protocol: "tcp",
      bytes_in: 45,
      bytes_out: 48000
    }
  },
  {
    id: 4,
    retryCount: 3,
    firstFailedAt: "2026-06-11T11:05:00.000Z",
    lastFailedAt: "2026-06-11T11:10:45.000Z",
    failureReason: "ERROR: invalid input syntax for type json. Malformed shap explanations payload column serialisation.",
    alertPayload: {
      time_epoch: 1781262300000,
      src_ip: "192.168.1.180",
      src_port: 4444,
      dst_ip: "172.16.0.4",
      dst_port: 443,
      protocol: "tcp",
      bytes_in: 850,
      bytes_out: 920
    }
  }
];
