<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import AppSidebar from "./components/AppSidebar.vue";
import EnvDetail from "./components/EnvDetail.vue";
import EnvDialog from "./components/EnvDialog.vue";
import SecretDetail from "./components/SecretDetail.vue";
import SecretDialog from "./components/SecretDialog.vue";
import SecretList from "./components/SecretList.vue";
import SettingsDialog from "./components/SettingsDialog.vue";
import type { DesktopStatus, EditableKind, EntryKind, EnvForm, SecretEntry, SecretForm } from "./types";
import { buildAddRequest, buildEditRequest, entryKind } from "./utils/entries";

const status = ref<DesktopStatus | null>(null);
const entries = ref<SecretEntry[]>([]);
const selectedId = ref("");
const filter = ref<EntryKind>("all");
const search = ref("");
const busy = ref(false);
const error = ref("");
const notice = ref("");
const showValues = ref(false);
const totpCodes = reactive<Record<string, string>>({});
const totpRemainingSeconds = ref(0);
const renderedEnv = ref("");
const secretDialogOpen = ref(false);
const envDialogOpen = ref(false);
const settingsDialogOpen = ref(false);
const dialogMode = ref<"add" | "edit">("add");
const dialogKind = ref<EditableKind>("password");
const editingEntry = ref<SecretEntry | null>(null);

const vaultForm = reactive({
  password: "",
  sessionMinutes: 30,
  usePassword: false,
});

const loginForm = reactive({
  password: "",
  sessionMinutes: 30,
});

const selectedEntry = computed(() => entries.value.find((entry) => entry.id === selectedId.value) ?? null);
const selectedKind = computed(() => (selectedEntry.value ? entryKind(selectedEntry.value) : ""));
const visibleEntries = computed(() => {
  const term = search.value.trim().toLowerCase();
  if (!term) return entries.value;
  return entries.value.filter((entry) => searchEntry(entry, term));
});
let totpTimeout: number | undefined;
let totpInterval: number | undefined;
let totpCountdownInterval: number | undefined;
let noticeTimeout: number | undefined;

onMounted(async () => {
  await refreshAll();
});

onBeforeUnmount(() => {
  stopTotpRefresh();
  clearNoticeTimer();
});

watch(
  () => selectedEntry.value?.id,
  () => {
    startTotpRefresh();
  },
);

async function run<T>(operation: () => Promise<T>, success?: string): Promise<T | undefined> {
  busy.value = true;
  error.value = "";
  notice.value = "";
  try {
    const result = await operation();
    if (success) showNotice(success);
    return result;
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  } finally {
    busy.value = false;
  }
}

function showNotice(message: string) {
  clearNoticeTimer();
  notice.value = message;
  noticeTimeout = window.setTimeout(() => {
    notice.value = "";
    noticeTimeout = undefined;
  }, 3000);
}

function clearNoticeTimer() {
  if (noticeTimeout !== undefined) {
    window.clearTimeout(noticeTimeout);
    noticeTimeout = undefined;
  }
}

async function refreshAll() {
  await run(async () => {
    status.value = await invoke<DesktopStatus>("vault_status");
    if (status.value.initialized && status.value.loggedIn) {
      await refreshEntries();
    } else {
      entries.value = [];
      selectedId.value = "";
    }
  });
}

async function refreshEntries() {
  const kind = filter.value === "all" ? null : filter.value;
  entries.value = await invoke<SecretEntry[]>("list_entries", { kind });
  if (!entries.value.some((entry) => entry.id === selectedId.value)) {
    selectedId.value = visibleEntries.value[0]?.id ?? "";
  }
}

async function changeFilter(value: EntryKind) {
  filter.value = value;
  search.value = "";
  renderedEnv.value = "";
  await run(refreshEntries);
}

function changeSearch(value: string) {
  search.value = value;
  if (!visibleEntries.value.some((entry) => entry.id === selectedId.value)) {
    selectedId.value = visibleEntries.value[0]?.id ?? "";
  }
}

async function initVault() {
  await run(
    async () => {
      await invoke("init_vault", {
        password: vaultForm.usePassword ? vaultForm.password : null,
        sessionMinutes: vaultForm.sessionMinutes,
      });
      vaultForm.password = "";
      await refreshAll();
    },
    "Vault initialized",
  );
}

async function loginVault() {
  await run(
    async () => {
      await invoke("login_vault", {
        password: loginForm.password,
        sessionMinutes: loginForm.sessionMinutes,
      });
      loginForm.password = "";
      await refreshAll();
    },
    "Vault unlocked",
  );
}

async function logoutVault() {
  await run(
    async () => {
      await invoke("logout_vault");
      await refreshAll();
    },
    "Vault locked",
  );
}

async function setVaultPassword(form: { password: string; confirmPassword: string; sessionMinutes: number }) {
  if (form.password !== form.confirmPassword) {
    error.value = "Passwords do not match";
    return;
  }
  if (!form.password) {
    error.value = "Password cannot be empty";
    return;
  }

  await run(
    async () => {
      await invoke("set_vault_password", {
        password: form.password,
        sessionMinutes: form.sessionMinutes,
      });
      settingsDialogOpen.value = false;
      await refreshAll();
    },
    "Login password saved",
  );
}

function openAddDialog() {
  editingEntry.value = null;
  dialogMode.value = "add";
  if (filter.value === "env") {
    envDialogOpen.value = true;
    return;
  }
  dialogKind.value = filter.value === "all" ? "password" : (filter.value as EditableKind);
  secretDialogOpen.value = true;
}

function openEditDialog() {
  if (!selectedEntry.value || selectedKind.value === "env") return;
  editingEntry.value = selectedEntry.value;
  dialogKind.value = selectedKind.value as EditableKind;
  dialogMode.value = "edit";
  secretDialogOpen.value = true;
}

async function submitSecretForm(form: SecretForm) {
  if (dialogMode.value === "edit" && editingEntry.value) {
    await run(
      async () => {
        await invoke("edit_entry", { request: buildEditRequest(form, editingEntry.value as SecretEntry) });
        secretDialogOpen.value = false;
        await refreshEntries();
      },
      "Entry updated",
    );
    return;
  }

  await run(
    async () => {
      await invoke("add_entry", { request: buildAddRequest(form) });
      secretDialogOpen.value = false;
      await refreshEntries();
    },
    "Entry saved",
  );
}

async function deleteSelected() {
  const entry = selectedEntry.value;
  if (!entry) return;
  await run(
    async () => {
      await invoke("delete_entry", {
        name: entry.id,
        kind: entryKind(entry),
      });
      await refreshEntries();
    },
    "Entry deleted",
  );
}

function startTotpRefresh() {
  stopTotpRefresh();
  const entry = selectedEntry.value;
  if (!entry || entryKind(entry) !== "totp") return;

  void refreshTotpCode(entry);
  const periodSeconds = typeof entry.kind.period === "number" && entry.kind.period > 0 ? entry.kind.period : 30;
  updateTotpRemaining(periodSeconds);
  totpCountdownInterval = window.setInterval(() => updateTotpRemaining(periodSeconds), 1000);

  const secondsUntilNextWindow = periodSeconds - (Math.floor(Date.now() / 1000) % periodSeconds);

  totpTimeout = window.setTimeout(() => {
    void refreshTotpCode(entry);
    totpInterval = window.setInterval(() => {
      void refreshTotpCode(entry);
    }, periodSeconds * 1000);
  }, secondsUntilNextWindow * 1000);
}

function stopTotpRefresh() {
  totpRemainingSeconds.value = 0;
  if (totpTimeout !== undefined) {
    window.clearTimeout(totpTimeout);
    totpTimeout = undefined;
  }
  if (totpInterval !== undefined) {
    window.clearInterval(totpInterval);
    totpInterval = undefined;
  }
  if (totpCountdownInterval !== undefined) {
    window.clearInterval(totpCountdownInterval);
    totpCountdownInterval = undefined;
  }
}

async function refreshTotpCode(entry: SecretEntry) {
  try {
    totpCodes[entry.id] = await invoke<string>("generate_totp_code", { name: entry.id });
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  }
}

function updateTotpRemaining(periodSeconds: number) {
  const elapsed = Math.floor(Date.now() / 1000) % periodSeconds;
  totpRemainingSeconds.value = periodSeconds - elapsed;
}

function searchEntry(entry: SecretEntry, term: string): boolean {
  const searchable = [
    entry.name,
    entryKind(entry),
    ...entry.tags,
    entry.notes ?? "",
    ...Object.values(entry.kind).flatMap((value) => {
      if (typeof value === "string" || typeof value === "number") return String(value);
      if (Array.isArray(value)) return value.map((item) => JSON.stringify(item));
      return [];
    }),
  ];
  return searchable.some((value) => value.toLowerCase().includes(term));
}

async function setEnvValue(form: EnvForm) {
  await run(
    async () => {
      await invoke("set_env_value", {
        request: {
          project: form.project,
          profile: form.profile,
          key: form.key,
          value: form.value,
        },
      });
      envDialogOpen.value = false;
      await refreshEntries();
    },
    "Env value saved",
  );
}

async function setEnvRef(form: EnvForm) {
  await run(
    async () => {
      await invoke("set_env_ref", {
        request: {
          project: form.project,
          profile: form.profile,
          key: form.key,
          refKind: form.refKind,
          secretName: form.secretName,
        },
      });
      envDialogOpen.value = false;
      await refreshEntries();
    },
    "Env reference saved",
  );
}

async function removeEnvValue(key: string) {
  const entry = selectedEntry.value;
  if (!entry) return;
  await run(
    async () => {
      await invoke("remove_env_value", {
        project: entry.kind.project,
        profile: entry.kind.profile,
        key,
      });
      await refreshEntries();
    },
    "Env key removed",
  );
}

async function renderEnv(project: string, profile: string) {
  await run(async () => {
    renderedEnv.value = await invoke<string>("render_env_profile", { project, profile });
  });
}

async function copyTotpCode() {
  const entry = selectedEntry.value;
  if (!entry) return;
  const code = totpCodes[entry.id];
  if (!code) return;

  await run(
    async () => {
      await navigator.clipboard.writeText(code);
    },
    "TOTP code copied",
  );
}

async function copySecretField(payload: { label: string; value: string }) {
  if (!payload.value) return;

  await run(
    async () => {
      await navigator.clipboard.writeText(payload.value);
    },
    `${payload.label} copied`,
  );
}
</script>

<template>
  <main class="shell">
    <AppSidebar
      :status="status"
      :filter="filter"
      :busy="busy"
      @update:filter="changeFilter"
      @refresh="refreshAll"
      @lock="logoutVault"
      @settings="settingsDialogOpen = true"
    />

    <section class="content">
      <header class="topbar">
        <div>
          <strong>{{ status?.initialized ? "Local encrypted vault" : "Create your vault" }}</strong>
          <span>{{ status?.vaultFile }}</span>
        </div>
        <label class="toggle">
          <input v-model="showValues" type="checkbox" />
          Reveal values
        </label>
      </header>

      <p v-if="error" class="message error">{{ error }}</p>
      <p v-if="notice" class="message notice">{{ notice }}</p>

      <form v-if="!status?.initialized" class="panel" @submit.prevent="initVault">
        <h2>Initialize</h2>
        <label class="check">
          <input v-model="vaultForm.usePassword" type="checkbox" />
          Require login password
        </label>
        <input
          v-if="vaultForm.usePassword"
          v-model="vaultForm.password"
          type="password"
          placeholder="Master password"
        />
        <input v-model.number="vaultForm.sessionMinutes" type="number" min="1" />
        <button :disabled="busy">Create Vault</button>
      </form>

      <form v-else-if="!status.loggedIn" class="panel" @submit.prevent="loginVault">
        <h2>Unlock</h2>
        <input v-model="loginForm.password" type="password" placeholder="Master password" />
        <input v-model.number="loginForm.sessionMinutes" type="number" min="1" />
        <button :disabled="busy">Unlock Vault</button>
      </form>

      <section v-else class="workspace">
        <SecretList
          :entries="visibleEntries"
          :selected-id="selectedId"
          :can-add="filter !== 'all'"
          :search="search"
          @update:search="changeSearch"
          @select="selectedId = $event"
          @add="openAddDialog"
        />

        <div class="detail">
          <EnvDetail
            v-if="selectedEntry && selectedKind === 'env'"
            :entry="selectedEntry"
            :rendered="renderedEnv"
            :busy="busy"
            :show-values="showValues"
            @set-value="setEnvValue"
            @set-ref="setEnvRef"
            @remove="removeEnvValue"
            @render="renderEnv"
          />
          <SecretDetail
            v-else-if="selectedEntry"
            :entry="selectedEntry"
            :show-values="showValues"
            :code="totpCodes[selectedEntry.id] ?? ''"
            :remaining-seconds="totpRemainingSeconds"
            :busy="busy"
            @edit="openEditDialog"
            @delete="deleteSelected"
            @copy-code="copyTotpCode"
            @copy-field="copySecretField"
          />
          <section v-else class="empty-state">
            <h2>No entries</h2>
            <button v-if="filter !== 'all'" class="with-icon" @click="openAddDialog">Add first entry</button>
          </section>
        </div>
      </section>
    </section>

    <SecretDialog
      :open="secretDialogOpen"
      :mode="dialogMode"
      :initial-kind="dialogKind"
      :entry="editingEntry"
      :busy="busy"
      @close="secretDialogOpen = false"
      @submit="submitSecretForm"
    />
    <EnvDialog
      :open="envDialogOpen"
      :entry="selectedKind === 'env' ? selectedEntry : null"
      :busy="busy"
      @close="envDialogOpen = false"
      @set-value="setEnvValue"
      @set-ref="setEnvRef"
    />
    <SettingsDialog
      :open="settingsDialogOpen"
      :busy="busy"
      @close="settingsDialogOpen = false"
      @set-password="setVaultPassword"
    />
  </main>
</template>
