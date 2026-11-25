/**
 * Typed client contracts for RedHand Enterprise modules:
 * - Ephemeral IAM Broker (/v1/iam/*)
 * - SIEM & STIX/TAXII 2.1 Threat Intel (/v1/siem/*)
 * - Async Deep Cyber-Model Escalation (/v1/escalation/*)
 */

import { apiFetch } from "./api";

export type IamProvider = "aws_sts" | "gcp_sts";

export interface CloudConnection {
  id: string;
  provider: IamProvider;
  display_name: string;
  principal_identifier: string;
  region_or_project: string;
  status: string;
  created_at: string | null;
}

export interface IamPolicy {
  id: string;
  external_agent_id: string;
  tool_name: string;
  provider: IamProvider;
  target_principal: string;
  target_resource: string;
  allowed_actions: string[];
  ttl_seconds: number;
  enabled: boolean;
  created_at: string | null;
}

export interface IamMintEvent {
  id: string;
  external_agent_id: string;
  tool_name: string;
  provider: IamProvider;
  token_jti: string;
  trace_id: string;
  span_id: string;
  outcome: "minted" | "denied";
  detail: string | null;
  expires_at: string | null;
  mint_latency_ms: number;
  created_at: string | null;
}

export interface IamOverviewResponse {
  connections: CloudConnection[];
  policies: IamPolicy[];
  recent_mints: IamMintEvent[];
  microsoft_entra_status: "coming_soon";
}

export const iamApi = {
  overview: (token: string | null) => apiFetch<IamOverviewResponse>("/v1/iam/overview", token),
  createConnection: (
    token: string | null,
    body: {
      provider: IamProvider;
      display_name: string;
      principal_identifier: string;
      region_or_project: string;
    }
  ) => apiFetch<CloudConnection>("/v1/iam/connections", token, { method: "POST", body }),
  deleteConnection: (token: string | null, id: string) =>
    apiFetch<{ deleted: boolean }>(`/v1/iam/connections/${encodeURIComponent(id)}`, token, { method: "DELETE" }),
  createPolicy: (
    token: string | null,
    body: {
      external_agent_id: string;
      tool_name: string;
      provider: IamProvider;
      target_principal: string;
      target_resource: string;
      allowed_actions: string[];
      ttl_seconds: number;
    }
  ) => apiFetch<IamPolicy>("/v1/iam/policies", token, { method: "POST", body }),
  deletePolicy: (token: string | null, id: string) =>
    apiFetch<{ deleted: boolean }>(`/v1/iam/policies/${encodeURIComponent(id)}`, token, { method: "DELETE" }),
};

export type ConnectorType = "splunk_hec" | "sentinel_logs" | "google_secops";

export interface SiemConnector {
  id: string;
  connector_type: ConnectorType;
  name: string;
  endpoint_url: string;
  token_hint: string;
  enabled: boolean;
  last_shipped_at: string | null;
  last_error: string | null;
  created_at: string | null;
}

export interface ThreatFeed {
  id: string;
  name: string;
  collection_url: string;
  token_hint: string | null;
  poll_interval_minutes: number;
  enabled: boolean;
  last_synced_at: string | null;
  last_indicator_count: number;
  last_error: string | null;
  created_at: string | null;
}

export interface ThreatIndicator {
  id: string;
  feed_id: string;
  indicator_type: "domain" | "ipv4" | "sha256";
  indicator_value: string;
  confidence: number;
  stix_id: string;
  created_at: string | null;
}

export interface SiemOverviewResponse {
  connectors: SiemConnector[];
  feeds: ThreatFeed[];
  indicators: ThreatIndicator[];
  outbox: { pending: number; delivered: number; dead_letter: number };
}

export interface SiemTestResult {
  delivered: boolean;
  status: "delivered" | "pending" | "dead_letter";
  detail: string;
}

export interface TaxiiSyncResult {
  feed_id: string;
  imported_count: number;
  status: "synced" | "failed";
  detail: string;
}

export const siemApi = {
  overview: (token: string | null) => apiFetch<SiemOverviewResponse>("/v1/siem/overview", token),
  createConnector: (
    token: string | null,
    body: {
      connector_type: ConnectorType;
      name: string;
      endpoint_url: string;
      auth_token: string;
    }
  ) => apiFetch<SiemConnector>("/v1/siem/connectors", token, { method: "POST", body }),
  deleteConnector: (token: string | null, id: string) =>
    apiFetch<{ deleted: boolean }>(`/v1/siem/connectors/${encodeURIComponent(id)}`, token, { method: "DELETE" }),
  testConnector: (token: string | null, id: string) =>
    apiFetch<SiemTestResult>(`/v1/siem/connectors/${encodeURIComponent(id)}/test`, token, { method: "POST" }),
  createFeed: (
    token: string | null,
    body: {
      name: string;
      collection_url: string;
      auth_token?: string | null;
      poll_interval_minutes: number;
    }
  ) => apiFetch<ThreatFeed>("/v1/siem/feeds", token, { method: "POST", body }),
  deleteFeed: (token: string | null, id: string) =>
    apiFetch<{ deleted: boolean }>(`/v1/siem/feeds/${encodeURIComponent(id)}`, token, { method: "DELETE" }),
  syncFeed: (token: string | null, id: string) =>
    apiFetch<TaxiiSyncResult>(`/v1/siem/feeds/${encodeURIComponent(id)}/sync`, token, { method: "POST" }),
};

export type TriggerKind = "onnx_borderline" | "delegation_depth" | "obfuscation_drift";
export type ModelProvider = "managed_redhand" | "anthropic" | "openai" | "gemini_vertex" | "custom_vpc";
export type BreakerAction = "freeze_agent" | "safe_mode" | "hitl_review";

export interface EscalationPolicy {
  id: string;
  name: string;
  trigger_kind: TriggerKind;
  threshold_value: number;
  provider: ModelProvider;
  endpoint_url: string;
  model_name: string;
  key_hint: string;
  circuit_breaker_action: BreakerAction;
  enabled: boolean;
  created_at: string | null;
}

export interface EscalationJob {
  id: string;
  policy_id: string;
  external_agent_id: string;
  trigger_kind: TriggerKind;
  signal_score: number;
  delegation_depth: number;
  redacted_trace: string;
  status: "pending" | "processing" | "completed" | "failed";
  verdict: "malicious" | "benign" | "inconclusive" | null;
  confidence: number | null;
  action_taken: string | null;
  reasoning_summary: string | null;
  review_latency_ms: number | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface EscalationOverviewResponse {
  policies: EscalationPolicy[];
  jobs: EscalationJob[];
}

export const escalationApi = {
  overview: (token: string | null) => apiFetch<EscalationOverviewResponse>("/v1/escalation/overview", token),
  createPolicy: (
    token: string | null,
    body: {
      name: string;
      trigger_kind: TriggerKind;
      threshold_value: number;
      provider: ModelProvider;
      endpoint_url: string;
      model_name: string;
      api_key?: string | null;
      circuit_breaker_action: BreakerAction;
    }
  ) => apiFetch<EscalationPolicy>("/v1/escalation/policies", token, { method: "POST", body }),
  deletePolicy: (token: string | null, id: string) =>
    apiFetch<{ deleted: boolean }>(`/v1/escalation/policies/${encodeURIComponent(id)}`, token, { method: "DELETE" }),
  evaluate: (
    token: string | null,
    body: {
      external_agent_id: string;
      trigger_kind: TriggerKind;
      signal_score: number;
      delegation_depth: number;
      trace_excerpt: string;
    }
  ) => apiFetch<EscalationJob>("/v1/escalation/evaluate", token, { method: "POST", body }),
};
