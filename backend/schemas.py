"""Strict API request models."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Literal, Any
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class FlowIn(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    flow_id: str|None=None; timestamp: str|None=None
    source_ip: str; destination_ip: str
    source_port: int=Field(ge=0,le=65535); destination_port: int=Field(ge=0,le=65535)
    protocol: str
    packet_count: float|None=Field(default=0,ge=0); byte_count: float=Field(ge=0); duration_seconds: float=Field(ge=0)
    connection_count: float=Field(default=0,ge=0); failed_connection_count: float=Field(default=0,ge=0)
    syn_count: float=Field(default=0,ge=0); rst_count: float=Field(default=0,ge=0)
    average_packet_size: float|None=Field(default=None,ge=0)
    unique_destination_ports: float=Field(default=1,ge=0); unique_destination_ips: float=Field(default=1,ge=0)
    label: str|None=None; scenario_type: str|None=None
    @field_validator("protocol")
    @classmethod
    def uppercase(cls,v): return v.upper()
    @model_validator(mode="after")
    def consistency(self):
        if self.connection_count>0 and self.failed_connection_count>self.connection_count: raise ValueError("failed_connection_count cannot exceed connection_count")
        return self
    def normalized(self):
        d=self.model_dump(); d["flow_id"]=d["flow_id"] or "FLOW-"+uuid4().hex[:12].upper(); d["timestamp"]=d["timestamp"] or datetime.now(timezone.utc).isoformat(); return d
class StatusUpdate(BaseModel):
    status: Literal["NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"]
    resolution_notes: str|None=Field(default=None,max_length=4000)
class NoteIn(BaseModel):
    note: str=Field(min_length=1,max_length=4000)
class RuleUpdate(BaseModel):
    threshold: float|list[int]|None=None; enabled: bool|None=None; severity: Literal["INFO","LOW","MEDIUM","HIGH","CRITICAL"]|None=None
