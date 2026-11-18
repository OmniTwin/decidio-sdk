/** The value model this SDK transports: exactly what JSON can carry, losslessly. */
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

/** Typed refusal for a value outside the canonical model. `decisionId` is set only when the
 *  refusal happens after a decision already exists (a direct-park caller). */
export class DecidioUnsafeArgumentsError extends Error {
  constructor(message: string, public decisionId?: string) {
    super(message);
    this.name = "DecidioUnsafeArgumentsError";
  }
}

const NOT_ROUTED = "The decision was NOT routed; nothing reached Decidio.";

function refuse(path: string, what: string, fix: string): never {
  throw new DecidioUnsafeArgumentsError(`[decidio] ${path} ${what} — the approval payload must be plain JSON so that what a human approves is exactly what executes; ${fix} ${NOT_ROUTED}`);
}

function assertNoLoneSurrogate(s: string, p: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) { i++; continue; }
      refuse(p, `contains an unpaired surrogate (U+${c.toString(16).toUpperCase()})`, "it cannot be encoded as UTF-8, so no wire or seal can carry it — repair the string (it is usually a split emoji or truncated UTF-16).");
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      refuse(p, `contains an unpaired surrogate (U+${c.toString(16).toUpperCase()})`, "it cannot be encoded as UTF-8, so no wire or seal can carry it — repair the string (it is usually a split emoji or truncated UTF-16).");
    }
  }
}

/** Deep-clone `value` into the canonical model, REFUSING anything that cannot be carried
 *  losslessly. Returns a fresh structure; the input is never referenced by the result. */
export function canonicalize<T = JsonValue>(value: unknown, path = "args"): T {
  return walk(value, path, new Set<object>()) as T;
}

function walk(v: unknown, p: string, seen: Set<object>): JsonValue {
  if (v === null) return null;
  const t = typeof v;
  if (t === "boolean") return v as JsonValue;
  if (t === "string") { assertNoLoneSurrogate(v as string, p); return v as JsonValue; }
  if (t === "number") {
    const n = v as number;
    if (!Number.isFinite(n)) refuse(p, `is ${String(n)}`, "a non-finite number becomes null in JSON, so the approver and your function would see different values — pass a finite number or a string.");
    if (Object.is(n, -0)) refuse(p, "is -0", "negative zero is indistinguishable from 0 after serialization — pass 0 if that is what you mean.");
    return n;
  }
  if (t === "undefined") refuse(p, "is undefined", "JSON drops or nullifies it — use null explicitly, or omit the field.");
  if (t === "bigint") refuse(p, "is a BigInt", "JSON cannot represent it — pass it as a string.");
  if (t === "function") refuse(p, "is a function", "it cannot be serialized for approval.");
  if (t === "symbol") refuse(p, "is a symbol", "it cannot be serialized for approval.");

  const o = v as object;
  if (seen.has(o)) refuse(p, "is part of a circular structure", "JSON cannot represent cycles — break the cycle or pass an id instead.");
  seen.add(o);
  try {
    const proto = Object.getPrototypeOf(o);
    if (Array.isArray(v)) {
      if (proto !== Array.prototype) refuse(p, "is an array subclass", "only plain arrays survive serialization with their behavior intact — pass a plain array.");
      const arr = v as unknown[];
      const keys = Reflect.ownKeys(arr);
      const expected = arr.length + 1;
      if (keys.length !== expected) {
        const extra = keys.filter((k) => k !== "length" && !(typeof k === "string" && /^\d+$/.test(k) && Number(k) < arr.length));
        if (extra.length) refuse(`${p}.${String(extra[0])}`, "is an extra property on an array", "JSON serializes arrays by index only, so it would be dropped — move it into an object.");
        refuse(p, "is a sparse array (it has holes)", "each hole becomes null in JSON — fill the holes or pass a dense array.");
      }
      return arr.map((x, i) => walk(x, `${p}[${i}]`, seen));
    }
    if (proto !== Object.prototype && proto !== null) {
      const name = (o as any)?.constructor?.name;
      refuse(p, `is ${name && name !== "Object" ? `a ${name}` : "an exotic object"}`, "only plain JSON objects survive serialization with their meaning intact (a Map becomes {}, a Date becomes a string) — convert it to plain JSON first.");
    }
    if (proto === null) refuse(p, "is a null-prototype object", "it round-trips into an ordinary object, changing its kind — pass a plain object.");
    if (typeof (o as any).toJSON === "function") refuse(p, "defines toJSON()", "its serialized form would differ from the value the approval and signature cover — pass the already-serialized form.");

    const out: Record<string, JsonValue> = {};
    for (const key of Reflect.ownKeys(o)) {
      if (typeof key === "symbol") refuse(p, "has a symbol-keyed property", "JSON drops symbol keys — use string keys.");
      const d = Object.getOwnPropertyDescriptor(o, key)!;
      if (!("value" in d)) refuse(`${p}.${key}`, "is a getter/setter", "an accessor is evaluated at serialization time, so the approved value could differ from the executed one — pass a plain data property.");
      if (!d.enumerable) refuse(`${p}.${key}`, "is a non-enumerable property", "JSON drops it, so the approver would never see it — make it enumerable or remove it.");
      assertNoLoneSurrogate(key, `${p}.${key}`);
      Object.defineProperty(out, key, {
        value: walk(d.value, `${p}.${key}`, seen),
        writable: true, enumerable: true, configurable: true,
      });
    }
    return out;
  } finally {
    seen.delete(o);
  }
}

function deepFreeze<T>(v: T): T {
  if (v === null || typeof v !== "object") return v;
  for (const k of Object.keys(v as object)) deepFreeze((v as Record<string, unknown>)[k]);
  return Object.freeze(v);
}

export function canonicalizeArgs(args: readonly unknown[]): JsonValue[] {
  return args.map((a, i) => deepFreeze(walk(a, `args[${i}]`, new Set<object>())));
}

/** RFC 8785-shaped canonical JSON of an already-canonical value — the exact bytes hashed for an
 *  execution report, so both languages produce the same digest. */
export function canonicalJson(value: JsonValue, path = "canonicalJson(...)"): string {
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") { assertNoLoneSurrogate(value, path); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map((v, i) => canonicalJson(v, `${path}[${i}]`)).join(",")}]`;
  const keys = Object.keys(value).sort();
  for (const k of keys) assertNoLoneSurrogate(k, `${path} key`);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k]!, `${path}.${k}`)}`).join(",")}}`;
}
