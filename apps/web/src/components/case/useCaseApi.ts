"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { isActive, type CaseEvent, type InvestigationCase } from "@/lib/cases";

export class RequestError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function detailOf(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown })?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (d as { msg?: string }).msg ?? "Invalid input").join("; ");
  return `Request failed (${status}).`;
}

export function caseApi(base: string) {
  async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${base}/${path}`, {
      ...init,
      headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}) },
      cache: "no-store",
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new RequestError(response.status, detailOf(body, response.status));
    return body as T;
  }
  return {
    get: <T,>(path: string) => call<T>(path),
    post: <T,>(path: string, body: unknown = {}) => call<T>(path, { method: "POST", body: JSON.stringify(body) }),
    del: <T,>(path: string) => call<T>(path, { method: "DELETE" }),
  };
}

/** Loads a case and polls it (and its event stream) while the investigation runs. */
export function useCase(base: string, caseId: string) {
  const api = useRef(caseApi(base)).current;
  const [data, setData] = useState<InvestigationCase | null>(null);
  const [events, setEvents] = useState<CaseEvent[]>([]);
  const [error, setError] = useState<string>("");
  const [tick, setTick] = useState(0);
  const lastSeq = useRef(0);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const [next, newEvents] = await Promise.all([
          api.get<InvestigationCase>(`cases/${caseId}`),
          api.get<CaseEvent[]>(`cases/${caseId}/events?after=${lastSeq.current}`),
        ]);
        if (cancelled) return;
        setData(next);
        if (newEvents.length) {
          lastSeq.current = newEvents[newEvents.length - 1].seq;
          setEvents((prev) => [...prev, ...newEvents]);
        }
        setError("");
        if (isActive(next.status)) timer = setTimeout(load, 650);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Could not load the case.");
      }
    }
    load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [api, caseId, tick]);

  return { api, data, events, error, refresh };
}
