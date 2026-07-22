// Supabase's SQL Editor can hand back a few different shapes depending on
// whether the user copies just the scan_result cell or the whole result
// row: a raw table array (the expected shape), that array wrapped in a
// single row object (`[{ scan_result: [...] }]`), or the row object on its
// own (`{ scan_result: [...] }`). This unwraps those known shapes into the
// plain array the rest of the app expects. It does not search arbitrary
// nested objects, and returns null (reject) rather than guess at anything
// else.
export function normalizeScanInput(parsed: unknown): unknown[] | null {
  if (Array.isArray(parsed)) {
    if (parsed.length === 1 && isScanResultWrapper(parsed[0])) {
      return unwrap(parsed[0]);
    }
    return parsed;
  }

  if (isScanResultWrapper(parsed)) {
    return unwrap(parsed);
  }

  return null;
}

function isScanResultWrapper(value: unknown): value is { scan_result: unknown } {
  return typeof value === "object" && value !== null && !Array.isArray(value) && "scan_result" in value;
}

function unwrap(wrapper: { scan_result: unknown }): unknown[] | null {
  return Array.isArray(wrapper.scan_result) ? wrapper.scan_result : null;
}
