import type { EditableKind, EnvForm, SecretEntry, SecretForm } from "../types";

export const kindFilters = ["all", "totp", "api-key", "password", "token", "env"] as const;
export const editableKinds = ["password", "api-key", "token", "totp"] as const;

export function createSecretForm(kind: EditableKind = "password"): SecretForm {
  return {
    kind,
    name: "",
    issuer: "",
    account: "",
    secret: "",
    digits: 6,
    period: 30,
    provider: "",
    scopes: "",
    username: "",
    password: "",
    url: "",
    service: "",
    token: "",
    tags: "",
    notes: "",
  };
}

export function createEnvForm(entry?: SecretEntry): EnvForm {
  return {
    project: entry ? textField(entry, "project") : "",
    profile: entry ? textField(entry, "profile") || "default" : "default",
    key: "",
    source: "literal",
    value: "",
    refKind: "api-key",
    secretName: "",
  };
}

export function formFromEntry(entry: SecretEntry): SecretForm {
  const kind = entryKind(entry) as EditableKind;
  return {
    kind,
    name: entry.name,
    issuer: textField(entry, "issuer"),
    account: textField(entry, "account"),
    secret: secretField(entry),
    digits: numberField(entry, "digits") || 6,
    period: numberField(entry, "period") || 30,
    provider: textField(entry, "provider"),
    scopes: arrayField(entry, "scopes").join(","),
    username: textField(entry, "username"),
    password: textField(entry, "password"),
    url: textField(entry, "url"),
    service: textField(entry, "service"),
    token: textField(entry, "token"),
    tags: entry.tags.join(","),
    notes: entry.notes ?? "",
  };
}

export function buildAddRequest(form: SecretForm) {
  const base = {
    kind: form.kind,
    name: form.name,
    tags: splitList(form.tags),
    notes: form.notes || null,
  };

  if (form.kind === "totp") {
    return {
      ...base,
      issuer: form.issuer || null,
      account: form.account || null,
      secret: form.secret,
      digits: form.digits,
      period: form.period,
    };
  }

  if (form.kind === "api-key") {
    return {
      ...base,
      provider: form.provider || null,
      key: form.secret,
      scopes: splitList(form.scopes),
    };
  }

  if (form.kind === "token") {
    return {
      ...base,
      service: form.service || null,
      token: form.secret,
    };
  }

  return {
    ...base,
    username: form.username || null,
    url: form.url || null,
    password: form.secret,
  };
}

export function buildEditRequest(form: SecretForm, original: SecretEntry) {
  const base = {
    kind: form.kind,
    name: original.id,
  };

  if (form.kind === "totp") {
    return {
      ...base,
      issuer: changed(form.issuer, textField(original, "issuer")),
      account: changed(form.account, textField(original, "account")),
      secret: changed(form.secret, textField(original, "secret")),
      digits: form.digits === numberField(original, "digits") ? null : form.digits,
      period: form.period === numberField(original, "period") ? null : form.period,
    };
  }

  if (form.kind === "api-key") {
    const scopes = splitList(form.scopes);
    return {
      ...base,
      provider: changed(form.provider, textField(original, "provider")),
      key: changed(form.secret, textField(original, "key")),
      scopes: scopes.join(",") === arrayField(original, "scopes").join(",") ? null : scopes,
    };
  }

  if (form.kind === "token") {
    return {
      ...base,
      service: changed(form.service, textField(original, "service")),
      token: changed(form.secret, textField(original, "token")),
    };
  }

  return {
    ...base,
    username: changed(form.username, textField(original, "username")),
    password: changed(form.secret, textField(original, "password")),
    url: changed(form.url, textField(original, "url")),
  };
}

export function entryKind(entry: SecretEntry): string {
  const kind = entry.kind.type;
  return typeof kind === "string" ? kind : "unknown";
}

export function entrySummary(entry: SecretEntry): string {
  const kind = entryKind(entry);
  if (kind === "totp") return textField(entry, "issuer") || textField(entry, "account") || "TOTP";
  if (kind === "api-key") return textField(entry, "provider") || "API key";
  if (kind === "password") return textField(entry, "username") || textField(entry, "url") || "Password";
  if (kind === "token") return textField(entry, "service") || "Token";
  if (kind === "env") return `${textField(entry, "project")}/${textField(entry, "profile")}`;
  return kind;
}

export function textField(entry: SecretEntry, field: string): string {
  const value = entry.kind[field];
  return typeof value === "string" ? value : "";
}

export function numberField(entry: SecretEntry, field: string): number {
  const value = entry.kind[field];
  return typeof value === "number" ? value : 0;
}

export function arrayField(entry: SecretEntry, field: string): string[] {
  const value = entry.kind[field];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function secretField(entry: SecretEntry): string {
  const kind = entryKind(entry);
  if (kind === "totp") return textField(entry, "secret");
  if (kind === "api-key") return textField(entry, "key");
  if (kind === "password") return textField(entry, "password");
  if (kind === "token") return textField(entry, "token");
  return "";
}

export function envVariables(entry: SecretEntry): NonNullable<SecretEntry["kind"]["variables"]> {
  return Array.isArray(entry.kind.variables) ? entry.kind.variables : [];
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function changed(next: string, previous: string): string | null {
  return next === previous ? null : next;
}
