// The `@aws-appsync/utils` module an APPSYNC_JS resolver imports, for fakecloud's
// data plane. It records what a resolver asks AppSync to do (errors, filters,
// invalidations, an early return) on `globalThis.__appsync`, which the Rust side
// sets before a run and reads after it. Functions it does not define are
// undefined, so calling one fails the resolver as AppSync fails an unknown call.
const host = globalThis.__appsync;

function stop(kind, detail) {
  const signal = new Error(kind);
  signal.__appsync = { kind, ...detail };
  throw signal;
}

const OPERATORS = new Set([
  "eq", "ne", "le", "lt", "ge", "gt", "contains", "notContains",
  "beginsWith", "in", "notIn", "between", "attributeExists",
]);

function filtersOf(object) {
  const filters = [];
  for (const [fieldName, condition] of Object.entries(object)) {
    if (fieldName === "or" || fieldName === "and") continue;
    if (condition === null || typeof condition !== "object") {
      throw new Error(`Invalid filter for ${fieldName}`);
    }
    for (const [operator, value] of Object.entries(condition)) {
      if (!OPERATORS.has(operator)) throw new Error(`Unsupported filter operator ${operator}`);
      filters.push({ fieldName, operator, value });
    }
  }
  return filters;
}

// `{a: {eq: 1}, or: [{b: {eq: 2}}, {c: {eq: 3}}]}` is (a = 1 and b = 2) or
// (a = 1 and c = 3): each `or` branch is a filter group that also carries the
// object's own conditions.
function toSubscriptionFilter(object) {
  if (object === null || typeof object !== "object") throw new Error("A filter is an object");
  const shared = filtersOf(object);
  const and = Array.isArray(object.and) ? object.and.flatMap((part) => filtersOf(part)) : [];
  const base = shared.concat(and);
  const branches = Array.isArray(object.or) ? object.or : [];
  const groups = branches.length
    ? branches.map((branch) => ({ filters: base.concat(filtersOf(branch)) }))
    : [{ filters: base }];
  return { filterGroup: groups };
}

function uuid() {
  const hex = [];
  for (let i = 0; i < 32; i += 1) hex.push(Math.floor(Math.random() * 16).toString(16));
  hex[12] = "4";
  hex[16] = ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16);
  const s = hex.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}

export const util = {
  authType: () => host.authType,
  // AppSync's util.matches is Java's String.matches: the whole string must match.
  matches: (pattern, value) => new RegExp(`^(?:${pattern})$`).test(String(value)),
  error: (message, errorType, data, errorInfo) =>
    stop("error", { message: String(message), errorType: errorType ?? null, data: data ?? null, errorInfo: errorInfo ?? null }),
  appendError: (message, errorType, data, errorInfo) => {
    host.errors.push({ message: String(message), errorType: errorType ?? null, data: data ?? null, errorInfo: errorInfo ?? null });
  },
  unauthorized: () => stop("unauthorized", {}),
  autoId: () => uuid(),
  autoUlid: () => uuid().replace(/-/g, "").slice(0, 26).toUpperCase(),
  isNull: (value) => value === null || value === undefined,
  isNullOrEmpty: (value) => value === null || value === undefined || value === "",
  isNullOrBlank: (value) => value === null || value === undefined || String(value).trim() === "",
  defaultIfNull: (value, fallback) => (value === null || value === undefined ? fallback : value),
  time: {
    nowISO8601: () => new Date().toISOString(),
    nowEpochSeconds: () => Math.floor(Date.now() / 1000),
    nowEpochMilliSeconds: () => Date.now(),
  },
  transform: { toSubscriptionFilter },
};

export const extensions = {
  setSubscriptionFilter: (filter) => {
    host.subscriptionFilter = filter;
  },
  setSubscriptionInvalidationFilter: (filter) => {
    host.invalidationFilter = filter;
  },
  invalidateSubscriptions: (request) => {
    host.invalidations.push(request);
  },
};

export const runtime = {
  earlyReturn: (value) => stop("earlyReturn", { value: value === undefined ? null : value }),
};
