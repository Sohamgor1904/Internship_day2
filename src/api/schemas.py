from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class EndpointSchema(BaseModel):
    ip: str = Field(..., description="IP address of the endpoint")
    port: int = Field(..., ge=0, le=65535, description="Port number of the endpoint")

class ConnectionInfoSchema(BaseModel):
    protocol_num: int = Field(..., description="IANA Protocol number (e.g. 6 for TCP, 17 for UDP)")
    protocol_name: Optional[str] = Field(None, description="Protocol name in lowercase string format")
    state: Optional[str] = Field(None, description="TCP state or connection state (e.g. FIN, CON, REQ)")

class TrafficSchema(BaseModel):
    bytes_in: int = Field(0, ge=0, description="Inbound bytes (destination to source)")
    bytes_out: int = Field(0, ge=0, description="Outbound bytes (source to destination)")
    packets_in: int = Field(0, ge=0, description="Inbound packets")
    packets_out: int = Field(0, ge=0, description="Outbound packets")

class MetadataSchema(BaseModel):
    product: Optional[Dict[str, Any]] = None
    version: Optional[str] = "1.1.0"

class OCSFNetworkTrafficSchema(BaseModel):
    class_uid: int = Field(4001, description="OCSF Class Unique Identifier (4001 for Network Traffic)")
    class_name: str = Field("Network Traffic", description="OCSF Class Name")
    activity_id: int = Field(1, description="Activity unique identifier")
    time: int = Field(..., description="Epoch milliseconds timestamp when event occurred")
    src_endpoint: EndpointSchema = Field(..., description="Source endpoint details")
    dst_endpoint: EndpointSchema = Field(..., description="Destination endpoint details")
    connection_info: ConnectionInfoSchema = Field(..., description="Connection protocol and state details")
    traffic: TrafficSchema = Field(default_factory=TrafficSchema, description="Volumetric flow sizes")
    severity_id: int = Field(1, description="Event severity identifier (0-6)")
    severity: Optional[str] = Field("Informational", description="Severity label matching severity_id")
    enrichments: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata enrichment store for testing and simulation labels")
    metadata: Optional[MetadataSchema] = Field(default_factory=MetadataSchema, description="Metadata about schema mapping")
