export type EntryKind = "all" | "totp" | "api-key" | "password" | "token" | "env";
export type EditableKind = Exclude<EntryKind, "all" | "env">;
export type EnvValueSource = "literal" | "secret-ref";

export interface DesktopStatus {
  initialized: boolean;
  authMode: string | null;
  loggedIn: boolean;
  vaultFile: string;
}

export interface EnvSecretRef {
  source: "secret-ref";
  kind: "api-key" | "token";
  name: string;
}

export interface EnvLiteral {
  source: "literal";
  value: string;
}

export interface EnvVariable {
  key: string;
  value: EnvLiteral | EnvSecretRef;
}

export interface SecretEntry {
  id: string;
  name: string;
  tags: string[];
  notes?: string | null;
  created_at: string;
  updated_at: string;
  kind: Record<string, unknown> & {
    type?: string;
    variables?: EnvVariable[];
  };
}

export interface SecretForm {
  kind: EditableKind;
  name: string;
  issuer: string;
  account: string;
  secret: string;
  digits: number;
  period: number;
  provider: string;
  scopes: string;
  username: string;
  password: string;
  url: string;
  service: string;
  token: string;
  tags: string;
  notes: string;
}

export interface EnvForm {
  project: string;
  profile: string;
  key: string;
  source: EnvValueSource;
  value: string;
  refKind: "api-key" | "token";
  secretName: string;
}
