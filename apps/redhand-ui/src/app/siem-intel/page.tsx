"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Database, Globe, Plus, Radio, RefreshCw, Send, ShieldCheck, Trash2 } from "lucide-react";

import { AppShell } from "@/components/shell/AppShell";
import { useRequiredSession } from "@/lib/auth";
import {
  type ConnectorType,
  type SiemOverviewResponse,
  siemApi,
} from "@/lib/enterprise";

const CONNECTOR_LABEL: Record<ConnectorType, string> = {
  splunk_hec: "Splunk HEC",
  sentinel_logs: "Microsoft Sentinel",
  google_secops: "Google SecOps",
};

export default function SiemIntelPage() {
  const session = useRequiredSession();
  const token = session?.token ?? null;

  const [data, setData] = useState<SiemOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Connector form
  const [connType, setConnType] = useState<ConnectorType>("splunk_hec");
  const [connName, setConnName] = useState("");
  const [connUrl, setConnUrl] = useState("");
  const [connToken, setConnToken] = useState("");

  // TAXII feed form
  const [feedName, setFeedName] = useState("");
  const [feedUrl, setFeedUrl] = useState("");
  const [feedToken, setFeedToken] = useState("");
  const [feedCadence, setFeedCadence] = useState(5);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await siemApi.overview(token);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load SIEM & Threat Intel overview.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleAddConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await siemApi.createConnector(token, {
        connector_type: connType,
        name: connName,
        endpoint_url: connUrl,
        auth_token: connToken,
      });
      setConnName("");
      setConnUrl("");
      setConnToken("");
      setNotice("SIEM connector saved with AES-256-GCM envelope encryption.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save SIEM connector.");
    } finally {
      setBusy(false);
    }
  };

  const handleTestConnector = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await siemApi.testConnector(token, id);
      if (res.delivered) setNotice(res.detail);
      else setError(`SIEM delivery (${res.status}): ${res.detail}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed sending OCSF test event.");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteConnector = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await siemApi.deleteConnector(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed deleting connector.");
    } finally {
      setBusy(false);
    }
  };

  const handleAddFeed = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await siemApi.createFeed(token, {
        name: feedName,
        collection_url: feedUrl,
        auth_token: feedToken.trim() || null,
        poll_interval_minutes: Number(feedCadence),
      });
      setFeedName("");
      setFeedUrl("");
      setFeedToken("");
      setNotice("STIX/TAXII 2.1 threat feed registered.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed adding TAXII feed.");
    } finally {
      setBusy(false);
    }
  };

  const handleSyncFeed = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await siemApi.syncFeed(token, id);
      if (res.status === "synced") setNotice(res.detail);
      else setError(res.detail);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Feed sync failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteFeed = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await siemApi.deleteFeed(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed deleting feed.");
    } finally {
      setBusy(false);
    }
  };

  const connectors = data?.connectors ?? [];
  const feeds = data?.feeds ?? [];
  const indicators = data?.indicators ?? [];
  const outbox = data?.outbox ?? { pending: 0, delivered: 0, dead_letter: 0 };

  return (
    <AppShell
      title="SIEM & Threat Intel"
      actions={
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading || busy}
          className="inline-flex items-center gap-1.5 rounded-rh-sm border border-control-border bg-rh-elevated px-3 py-1.5 text-xs font-medium text-rh-text-2 hover:bg-control-glassHover hover:text-rh-text"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      }
    >
      <div className="flex flex-col gap-5">
        {error && (
          <div role="alert" className="rounded-rh-md border border-control-crimsonBorder bg-control-crimsonSoft px-4 py-3 text-xs text-rh-crimson-text">
            {error}
          </div>
        )}
        {notice && (
          <div className="rounded-rh-md border border-rh-teal-border bg-rh-teal-wash px-4 py-3 text-xs text-rh-teal-text">
            {notice}
          </div>
        )}

        {/* OCSF Outbox & Feed Summary */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>OCSF Delivered</span>
              <ShieldCheck className="h-4 w-4 text-rh-teal-text" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-teal-text">{outbox.delivered}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">OCSF v1.1.0 events shipped</div>
          </div>
          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>Outbox Pending</span>
              <Database className="h-4 w-4 text-rh-ochre" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-text">{outbox.pending}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">Dead-letter: {outbox.dead_letter}</div>
          </div>
          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>TAXII 2.1 Feeds</span>
              <Radio className="h-4 w-4 text-rh-steel-text" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-text">{feeds.length}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">SSRF &amp; DNS-pinned polling</div>
          </div>
          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>Synced IOCs</span>
              <Globe className="h-4 w-4 text-rh-ochre" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-text">{indicators.length}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">Domains, IPv4 &amp; SHA-256</div>
          </div>
        </div>

        {/* Forms */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <form onSubmit={handleAddConnector} className="rh-glass flex flex-col gap-3 rounded-rh-xl border border-control-border p-4">
            <div className="flex items-center justify-between border-b border-control-border pb-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-rh-text">Add OCSF v1.1.0 SIEM Connector</h2>
              <span className="font-mono text-[10px] text-rh-teal-text">AES-256-GCM VAULT</span>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <select
                value={connType}
                onChange={(e) => setConnType(e.target.value as ConnectorType)}
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              >
                <option value="splunk_hec">Splunk Enterprise HEC</option>
                <option value="sentinel_logs">Microsoft Sentinel Logs</option>
                <option value="google_secops">Google SecOps (Chronicle)</option>
              </select>
              <input
                required
                value={connName}
                onChange={(e) => setConnName(e.target.value)}
                placeholder="Connector label (e.g. Splunk SOC)"
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              />
            </div>
            <input
              required
              type="url"
              value={connUrl}
              onChange={(e) => setConnUrl(e.target.value)}
              placeholder="https://splunk.example.com/services/collector"
              className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
            />
            <div className="flex items-center gap-2.5">
              <input
                required
                type="password"
                value={connToken}
                onChange={(e) => setConnToken(e.target.value)}
                placeholder="HEC / Ingestion Bearer Token (encrypted at rest)"
                className="flex-1 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-rh-sm bg-control-crimsonDeep px-4 py-2 text-xs font-semibold text-rh-text hover:bg-control-crimson disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Add Sink</span>
              </button>
            </div>
          </form>

          <form onSubmit={handleAddFeed} className="rh-glass flex flex-col gap-3 rounded-rh-xl border border-control-border p-4">
            <div className="flex items-center justify-between border-b border-control-border pb-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-rh-text">Add STIX/TAXII 2.1 Feed</h2>
              <span className="font-mono text-[10px] text-rh-steel-text">COLLECTION POLLER</span>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <input
                required
                value={feedName}
                onChange={(e) => setFeedName(e.target.value)}
                placeholder="Feed name (e.g. MISP SOC)"
                className="sm:col-span-2 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              />
              <input
                type="number"
                min={1}
                max={1440}
                value={feedCadence}
                onChange={(e) => setFeedCadence(Number(e.target.value))}
                placeholder="Minutes"
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
            </div>
            <input
              required
              type="url"
              value={feedUrl}
              onChange={(e) => setFeedUrl(e.target.value)}
              placeholder="https://taxii.example.com/collections/1/objects/"
              className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
            />
            <div className="flex items-center gap-2.5">
              <input
                type="password"
                value={feedToken}
                onChange={(e) => setFeedToken(e.target.value)}
                placeholder="Optional TAXII Bearer Token"
                className="flex-1 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-rh-sm bg-control-crimsonDeep px-4 py-2 text-xs font-semibold text-rh-text hover:bg-control-crimson disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Add Feed</span>
              </button>
            </div>
          </form>
        </div>

        {/* Connectors Table */}
        <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
          <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
            <span className="text-xs font-semibold text-rh-text">Configured OCSF SIEM Connectors</span>
            <span className="font-mono text-[10px] text-rh-text-2">{connectors.length} SINKS</span>
          </div>
          {connectors.length === 0 ? (
            <p className="px-4 py-6 text-xs text-rh-text-muted">No SIEM connectors configured yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Name</th>
                    <th className="px-4 py-2.5">Type</th>
                    <th className="px-4 py-2.5">Endpoint</th>
                    <th className="px-4 py-2.5">Token</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {connectors.map((c) => (
                    <tr key={c.id} className="text-rh-text-2">
                      <td className="px-4 py-3 font-semibold text-rh-text">{c.name}</td>
                      <td className="px-4 py-3">{CONNECTOR_LABEL[c.connector_type]}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{c.endpoint_url}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{c.token_hint}</td>
                      <td className="px-4 py-3 text-[11px]">
                        {c.last_error ? (
                          <span className="text-rh-crimson-text">{c.last_error}</span>
                        ) : c.last_shipped_at ? (
                          <span className="text-rh-teal-text">Delivered</span>
                        ) : (
                          <span className="text-rh-text-muted">Ready</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void handleTestConnector(c.id)}
                            className="inline-flex items-center gap-1 rounded-rh-sm border border-control-border bg-rh-elevated px-2.5 py-1 text-[11px] text-rh-text hover:bg-control-glassHover"
                          >
                            <Send className="h-3 w-3" />
                            <span>Test OCSF</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDeleteConnector(c.id)}
                            aria-label={`Delete ${c.name}`}
                            className="rounded-rh-sm p-1 text-rh-crimson-text hover:bg-control-crimsonSoft"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* TAXII Feeds & Synced Indicators */}
        <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
          <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
            <span className="text-xs font-semibold text-rh-text">STIX/TAXII 2.1 Threat Feeds</span>
            <span className="font-mono text-[10px] text-rh-text-2">{feeds.length} FEEDS</span>
          </div>
          {feeds.length === 0 ? (
            <p className="px-4 py-6 text-xs text-rh-text-muted">No TAXII feeds registered yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Feed</th>
                    <th className="px-4 py-2.5">Collection URL</th>
                    <th className="px-4 py-2.5">Indicators</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {feeds.map((f) => (
                    <tr key={f.id} className="text-rh-text-2">
                      <td className="px-4 py-3 font-semibold text-rh-text">{f.name}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{f.collection_url}</td>
                      <td className="rh-tabular px-4 py-3 font-mono">{f.last_indicator_count}</td>
                      <td className="px-4 py-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void handleSyncFeed(f.id)}
                            className="inline-flex items-center gap-1 rounded-rh-sm border border-control-border bg-rh-elevated px-2.5 py-1 text-[11px] text-rh-text hover:bg-control-glassHover"
                          >
                            <RefreshCw className="h-3 w-3" />
                            <span>Sync Now</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDeleteFeed(f.id)}
                            aria-label={`Delete ${f.name}`}
                            className="rounded-rh-sm p-1 text-rh-crimson-text hover:bg-control-crimsonSoft"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {indicators.length > 0 && (
          <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
            <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
              <span className="text-xs font-semibold text-rh-text">Synced STIX Indicators</span>
              <span className="font-mono text-[10px] text-rh-teal-text">{indicators.length} ACTIVE</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Type</th>
                    <th className="px-4 py-2.5">Indicator</th>
                    <th className="px-4 py-2.5">Confidence</th>
                    <th className="px-4 py-2.5">STIX ID</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {indicators.map((ind) => (
                    <tr key={ind.id} className="text-rh-text-2">
                      <td className="px-4 py-2.5 font-mono uppercase text-rh-ochre">{ind.indicator_type}</td>
                      <td className="px-4 py-2.5 font-mono text-rh-text">{ind.indicator_value}</td>
                      <td className="rh-tabular px-4 py-2.5 font-mono">{ind.confidence}%</td>
                      <td className="px-4 py-2.5 font-mono text-[11px]">{ind.stix_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
