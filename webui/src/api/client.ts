import type {
  ApiErrorEnvelope,
  ApiErrorShape,
} from "@/api/types";

const TOKEN_KEY = "netattackai.apiToken.v1";

export function getStoredToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setStoredToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Ignore storage failures (private mode, etc.).
  }
}

export function clearStoredToken(): void {
  setStoredToken("");
}

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;
  requestId: string;
  raw: unknown;

  constructor(shape: ApiErrorShape) {
    super(shape.message || `API error ${shape.status}`);
    this.name = "ApiError";
    this.status = shape.status;
    this.code = shape.code;
    this.details = shape.details;
    this.requestId = shape.requestId;
    this.raw = shape.raw;
  }

  get isAuth(): boolean {
    return this.status === 401;
  }

  get isConflict(): boolean {
    return this.status === 409;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

interface FetchOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  raw?: boolean;
}

const API_PREFIX = "/api/v1";

export async function apiFetch<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers ?? {}),
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined && options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
  }

  const url = path.startsWith("http") || path.startsWith("/api/") ? path : `${API_PREFIX}${path}`;
  const init: RequestInit = {
    method: options.method ?? "GET",
    headers,
    signal: options.signal,
  };
  if (options.body !== undefined && options.method && options.method !== "GET") {
    init.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }

  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError({
      status: 0,
      code: "network",
      message: err instanceof Error ? err.message : "Network request failed",
      details: {},
      requestId: "",
      raw: err,
    });
  }

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");

  if (options.raw && !response.ok) {
    const rawBody = isJson ? await response.json().catch(() => null) : await response.text().catch(() => null);
    throw normalizeError(response.status, rawBody);
  }

  if (!response.ok) {
    const rawBody = isJson ? await response.json().catch(() => null) : await response.text().catch(() => null);
    throw normalizeError(response.status, rawBody);
  }

  if (options.raw) return (await response.blob()) as unknown as T;
  if (!isJson) return (await response.text()) as unknown as T;
  return (await response.json()) as T;
}

function normalizeError(status: number, body: unknown): ApiError {
  if (body && typeof body === "object" && "error" in body) {
    const env = body as ApiErrorEnvelope;
    const err = env.error;
    return new ApiError({
      status,
      code: err.code,
      message: err.message,
      details: err.details ?? {},
      requestId: err.request_id ?? "",
      raw: body,
    });
  }
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    const message = typeof detail === "string" ? detail : "Request validation failed";
    return new ApiError({
      status,
      code: "http_error",
      message,
      details: { detail },
      requestId: "",
      raw: body,
    });
  }
  const text = typeof body === "string" ? body : responseStatusText(status);
  return new ApiError({
    status,
    code: "http_error",
    message: text || `Request failed (${status})`,
    details: {},
    requestId: "",
    raw: body,
  });
}

function responseStatusText(status: number): string {
  const map: Record<number, string> = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    409: "Conflict",
    422: "Validation failed",
    500: "Server error",
    502: "Bad gateway",
    503: "Service unavailable",
    504: "Gateway timeout",
  };
  return map[status] ?? "";
}

export function wsUrlForRun(runId: string): string {
  const token = getStoredToken();
  const loc = window.location;
  const scheme = loc.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${loc.host}/api/v1/ws/v1/runs/${encodeURIComponent(runId)}?token=${encodeURIComponent(token)}`;
}

export function sseUrlForRun(runId: string, after: number): string {
  const token = getStoredToken();
  const loc = window.location;
  return `${loc.origin}/api/v1/runs/${encodeURIComponent(runId)}/events/stream?after=${after}&token=${encodeURIComponent(token)}`;
}