"""Typed objects produced by discovery."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RawScan(BaseModel):
    """Raw command outputs collected from one target."""

    target: str
    outputs: dict[str, str] = Field(default_factory=dict)
    errors: dict[str, str] = Field(default_factory=dict)


class Host(BaseModel):
    name: str
    target: str
    ips: list[str] = Field(default_factory=list)
    attrs: dict[str, str] = Field(default_factory=dict)


class Software(BaseModel):
    host: str
    name: str
    version: str | None = None
    process: str | None = None
    attrs: dict[str, str] = Field(default_factory=dict)


class Process(BaseModel):
    host: str
    pid: int
    user: str
    name: str
    cmd: str


class Listener(BaseModel):
    host: str
    proto: str
    address: str
    port: int
    process: str | None = None


class Connection(BaseModel):
    host: str
    local_ip: str
    local_port: int
    peer_ip: str
    peer_port: int
    process: str | None = None


class Inventory(BaseModel):
    """Everything inferred about one host from a single scan."""

    host: Host
    software: list[Software] = Field(default_factory=list)
    processes: list[Process] = Field(default_factory=list)
    listeners: list[Listener] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
