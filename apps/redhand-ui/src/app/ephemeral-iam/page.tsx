"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Cloud, KeyRound, Plus, RefreshCw, ShieldCheck, Timer, Trash2 } from "lucide-react";

import { AppShell } from "@/components/shell/AppShell";
import { useRequiredSession } from "@/lib/auth";
import {
  type IamOverviewResponse,
  type IamProvider,
  iamApi,
} from "@/lib/enterprise";

const PROVIDER_LABEL: Record<IamProvider, string> = {
  aws_sts: "AWS STS (AssumeRole)",
  gcp_sts: "GCP STS (Access Boundary)",
};

export default function EphemeralIamPage() {
  const session = useRequiredSession();
  const token = session?.token ?? null;

  const [data, setData] = useState<IamOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Cloud connection form state
  const [connProvider, setConnProvider] = useState<IamProvider>("aws_sts");
  const [connName, setConnName] = useState("");
  const [connPrincipal, setConnPrincipal] = useState("");
  const [connRegion, setConnRegion] = useState("us-east-1");

  // Policy form state
  const [polAgent, setPolAgent] = useState("");
  const [polTool, setPolTool] = useState("");
  const [polProvider, setPolProvider] = useState<IamProvider>("gcp_sts");
  const [polPrincipal, setPolPrincipal] = useState("");
  const [polResource, setPolResource] = useState("");
  const [polActions, setPolActions] = useState("storage.objects.get");
  const [polTtl, setPolTtl] = useState(60);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const res = await iamApi.overview(token);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load Ephemeral IAM overview.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleAddConnection = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await iamApi.createConnection(token, {
        provider: connProvider,
        display_name: connName,
        principal_identifier: connPrincipal,
        region_or_project: connRegion,
      });
      setConnName("");
      setConnPrincipal("");
      setNotice("Cloud trust connection registered.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save cloud connection.");
    } finally {
      setBusy(false);
    }
  };

  const handleAddPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await iamApi.createPolicy(token, {
        external_agent_id: polAgent,
        tool_name: polTool,
        provider: polProvider,
        target_principal: polPrincipal,
        target_resource: polResource,
        allowed_actions: polActions
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        ttl_seconds: Number(polTtl),
      });
      setPolAgent("");
      setPolTool("");
      setPolResource("");
      setNotice("Turn-scoped IAM downscoping policy saved.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save IAM policy.");
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteConnection = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await iamApi.deleteConnection(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete connection.");
    } finally {
      setBusy(false);
    }
  };

  const handleDeletePolicy = async (id: string) => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await iamApi.deletePolicy(token, id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete policy.");
    } finally {
      setBusy(false);
    }
  };

  const connections = data?.connections ?? [];
  const policies = data?.policies ?? [];
  const mints = data?.recent_mints ?? [];

  return (
    <AppShell
      title="Ephemeral IAM Broker"
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

        {/* KPI Strip */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>Cloud Connections</span>
              <Cloud className="h-4 w-4 text-rh-steel-text" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-text">{connections.length}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">AWS STS &amp; GCP IAM active</div>
          </div>

          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>Downscoping Policies</span>
              <ShieldCheck className="h-4 w-4 text-rh-teal-text" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-teal-text">{policies.length}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">Wildcard &lsquo;*&rsquo; resources blocked</div>
          </div>

          <div className="rh-glass rounded-rh-lg border border-control-border p-4">
            <div className="flex items-center justify-between text-xs text-rh-text-2">
              <span>Recent Token Mints</span>
              <KeyRound className="h-4 w-4 text-rh-ochre" />
            </div>
            <div className="rh-tabular mt-2 font-mono text-2xl font-bold text-rh-text">{mints.length}</div>
            <div className="mt-1 text-[11px] text-rh-text-muted">Passport-bound JIT sessions</div>
          </div>

          <div className="rh-glass rounded-rh-lg border border-rh-ochre-border bg-rh-ochre-wash/20 p-4">
            <div className="flex items-center justify-between text-xs text-rh-ochre">
              <span>Microsoft Entra ID OBO</span>
              <Timer className="h-4 w-4" />
            </div>
            <div className="mt-2 font-mono text-sm font-bold uppercase tracking-wide text-rh-ochre">COMING SOON</div>
            <div className="mt-1 text-[11px] text-rh-text-2">Entra OBO delegated exchange in v1.1</div>
          </div>
        </div>

        {/* Registration Forms */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <form onSubmit={handleAddConnection} className="rh-glass flex flex-col gap-3 rounded-rh-xl border border-control-border p-4">
            <div className="flex items-center justify-between border-b border-control-border pb-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-rh-text">Register Cloud Trust Principal</h2>
              <span className="font-mono text-[10px] text-rh-text-muted">ADMIN</span>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <select
                value={connProvider}
                onChange={(e) => setConnProvider(e.target.value as IamProvider)}
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              >
                <option value="aws_sts">AWS STS Role ARN</option>
                <option value="gcp_sts">GCP Service Account</option>
              </select>
              <input
                required
                value={connName}
                onChange={(e) => setConnName(e.target.value)}
                placeholder="Display name (e.g. Prod Read Role)"
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text placeholder:text-rh-text-muted"
              />
            </div>
            <input
              required
              value={connPrincipal}
              onChange={(e) => setConnPrincipal(e.target.value)}
              placeholder={
                connProvider === "aws_sts"
                  ? "arn:aws:iam::123456789012:role/redhand-turn-ro"
                  : "sa-finops@my-project.iam.gserviceaccount.com"
              }
              className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text placeholder:text-rh-text-muted"
            />
            <div className="flex items-center gap-2.5">
              <input
                required
                value={connRegion}
                onChange={(e) => setConnRegion(e.target.value)}
                placeholder="Region or GCP Project ID"
                className="flex-1 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-rh-sm bg-control-crimsonDeep px-4 py-2 text-xs font-semibold text-rh-text hover:bg-control-crimson disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Add Connection</span>
              </button>
            </div>
          </form>

          <form onSubmit={handleAddPolicy} className="rh-glass flex flex-col gap-3 rounded-rh-xl border border-control-border p-4">
            <div className="flex items-center justify-between border-b border-control-border pb-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-rh-text">Create Downscoping Policy</h2>
              <span className="font-mono text-[10px] text-rh-teal-text">FAIL-CLOSED BOUNDARY</span>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <input
                required
                value={polAgent}
                onChange={(e) => setPolAgent(e.target.value)}
                placeholder="Agent external ID"
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <input
                required
                value={polTool}
                onChange={(e) => setPolTool(e.target.value)}
                placeholder="Tool name"
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <select
                value={polProvider}
                onChange={(e) => {
                  const next = e.target.value as IamProvider;
                  setPolProvider(next);
                  setPolTtl(next === "aws_sts" ? 900 : 60);
                }}
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 text-xs text-rh-text"
              >
                <option value="gcp_sts">GCP STS (≤60s)</option>
                <option value="aws_sts">AWS STS (≥900s)</option>
              </select>
            </div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <input
                required
                value={polPrincipal}
                onChange={(e) => setPolPrincipal(e.target.value)}
                placeholder={
                  polProvider === "aws_sts"
                    ? "arn:aws:iam::123456789012:role/redhand-ro"
                    : "sa@project.iam.gserviceaccount.com"
                }
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <input
                required
                value={polResource}
                onChange={(e) => setPolResource(e.target.value)}
                placeholder={
                  polProvider === "aws_sts"
                    ? "arn:aws:s3:::kb-bucket/docs/*"
                    : "//storage.googleapis.com/projects/_/buckets/kb-bucket"
                }
                className="rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <input
                required
                value={polActions}
                onChange={(e) => setPolActions(e.target.value)}
                placeholder="Comma-separated permissions (e.g. storage.objects.get)"
                className="min-w-[200px] flex-1 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <input
                type="number"
                min={15}
                max={43200}
                value={polTtl}
                onChange={(e) => setPolTtl(Number(e.target.value))}
                className="w-24 rounded-rh-sm border border-control-border bg-rh-subtle px-3 py-2 font-mono text-xs text-rh-text"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-rh-sm bg-control-crimsonDeep px-4 py-2 text-xs font-semibold text-rh-text hover:bg-control-crimson disabled:opacity-50"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Save Policy</span>
              </button>
            </div>
          </form>
        </div>

        {/* Registered Connections */}
        <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
          <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
            <span className="text-xs font-semibold text-rh-text">Configured Cloud Trust Principals</span>
            <span className="font-mono text-[10px] text-rh-text-2">{connections.length} ACTIVE</span>
          </div>
          {connections.length === 0 ? (
            <p className="px-4 py-6 text-xs text-rh-text-muted">No cloud trust connections configured yet. Register an AWS Role ARN or GCP Service Account above.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Name</th>
                    <th className="px-4 py-2.5">Provider</th>
                    <th className="px-4 py-2.5">Principal</th>
                    <th className="px-4 py-2.5">Region / Project</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {connections.map((c) => (
                    <tr key={c.id} className="text-rh-text-2">
                      <td className="px-4 py-3 font-semibold text-rh-text">{c.display_name}</td>
                      <td className="px-4 py-3">{PROVIDER_LABEL[c.provider]}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{c.principal_identifier}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{c.region_or_project}</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => void handleDeleteConnection(c.id)}
                          aria-label={`Delete ${c.display_name}`}
                          className="inline-flex items-center gap-1 rounded-rh-sm px-2 py-1 text-rh-crimson-text hover:bg-control-crimsonSoft"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Active Downscoping Policies */}
        <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
          <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
            <span className="text-xs font-semibold text-rh-text">Turn-Scoped Downscoping Policies</span>
            <span className="font-mono text-[10px] text-rh-teal-text">ENFORCED ON /V1/IAM/MINT/*</span>
          </div>
          {policies.length === 0 ? (
            <p className="px-4 py-6 text-xs text-rh-text-muted">No custom downscoping boundaries defined yet; passport tool scopes still govern `/v1/iam/mint/*` calls.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Agent · Tool</th>
                    <th className="px-4 py-2.5">Provider</th>
                    <th className="px-4 py-2.5">Resource Boundary</th>
                    <th className="px-4 py-2.5">Permissions</th>
                    <th className="px-4 py-2.5">TTL</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {policies.map((p) => (
                    <tr key={p.id} className="text-rh-text-2">
                      <td className="px-4 py-3 font-mono font-semibold text-rh-text">
                        {p.external_agent_id} <span className="text-rh-text-muted">/ {p.tool_name}</span>
                      </td>
                      <td className="px-4 py-3">{PROVIDER_LABEL[p.provider]}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{p.target_resource}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{p.allowed_actions.join(", ")}</td>
                      <td className="px-4 py-3 font-mono text-rh-ochre">{p.ttl_seconds}s</td>
                      <td className="px-4 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => void handleDeletePolicy(p.id)}
                          aria-label={`Delete policy ${p.tool_name}`}
                          className="inline-flex items-center gap-1 rounded-rh-sm px-2 py-1 text-rh-crimson-text hover:bg-control-crimsonSoft"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Live Token Mint Audit Ledger */}
        <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
          <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
            <span className="text-xs font-semibold text-rh-text">Live Ephemeral Token Mint Audit Trail</span>
            <span className="font-mono text-[10px] text-rh-text-2">APPEND-ONLY</span>
          </div>
          {mints.length === 0 ? (
            <p className="px-4 py-6 text-xs text-rh-text-muted">No token mints recorded yet for this organization.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Agent · Tool</th>
                    <th className="px-4 py-2.5">Cloud</th>
                    <th className="px-4 py-2.5">JTI Fingerprint</th>
                    <th className="px-4 py-2.5">Latency</th>
                    <th className="px-4 py-2.5">Outcome</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {mints.map((m) => (
                    <tr key={m.id} className="text-rh-text-2">
                      <td className="px-4 py-3 font-mono text-rh-text">{m.external_agent_id} / {m.tool_name}</td>
                      <td className="px-4 py-3">{PROVIDER_LABEL[m.provider]}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{m.token_jti}</td>
                      <td className="rh-tabular px-4 py-3 font-mono">{m.mint_latency_ms.toFixed(1)}ms</td>
                      <td className="px-4 py-3">
                        <span className="rounded-full border border-rh-teal-border bg-rh-teal-wash px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-rh-teal-text">
                          {m.outcome}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
