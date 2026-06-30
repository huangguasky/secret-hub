<script setup lang="ts">
import { computed, reactive, watch } from "vue";
import type { EditableKind, SecretEntry, SecretForm } from "../types";
import { createSecretForm, editableKinds, formFromEntry } from "../utils/entries";

const props = defineProps<{
  open: boolean;
  mode: "add" | "edit";
  initialKind: EditableKind;
  entry: SecretEntry | null;
  busy: boolean;
}>();

const emit = defineEmits<{
  (event: "close"): void;
  (event: "submit", form: SecretForm): void;
}>();

const form = reactive<SecretForm>(createSecretForm());
const title = computed(() => (props.mode === "add" ? "Add Secret" : "Edit Secret"));
const secretLabel = computed(() => {
  if (form.kind === "api-key") return "API key";
  if (form.kind === "token") return "Token";
  if (form.kind === "totp") return "TOTP secret";
  return "Password";
});

watch(
  () => [props.open, props.mode, props.initialKind, props.entry] as const,
  () => {
    const next = props.mode === "edit" && props.entry ? formFromEntry(props.entry) : createSecretForm(props.initialKind);
    Object.assign(form, next);
  },
  { immediate: true },
);

function submit() {
  emit("submit", { ...form });
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
    <form class="modal" @submit.prevent="submit">
      <header class="modal-head">
        <h2>{{ title }}</h2>
        <button type="button" class="icon-button" title="Close" @click="$emit('close')">×</button>
      </header>

      <div class="grid">
        <label>
          <span>Type</span>
          <select v-model="form.kind" :disabled="mode === 'edit'">
            <option v-for="kind in editableKinds" :key="kind" :value="kind">{{ kind }}</option>
          </select>
        </label>
        <label>
          <span>Name</span>
          <input v-model="form.name" :disabled="mode === 'edit'" required />
        </label>
      </div>

      <div v-if="form.kind === 'password'" class="grid">
        <label>
          <span>Username</span>
          <input v-model="form.username" />
        </label>
        <label>
          <span>URL</span>
          <input v-model="form.url" />
        </label>
      </div>

      <div v-if="form.kind === 'api-key'" class="grid">
        <label>
          <span>Provider</span>
          <input v-model="form.provider" />
        </label>
        <label>
          <span>Scopes</span>
          <input v-model="form.scopes" placeholder="repo,read:user" />
        </label>
      </div>

      <div v-if="form.kind === 'token'" class="grid">
        <label>
          <span>Service</span>
          <input v-model="form.service" />
        </label>
      </div>

      <div v-if="form.kind === 'totp'" class="grid">
        <label>
          <span>Issuer</span>
          <input v-model="form.issuer" />
        </label>
        <label>
          <span>Account</span>
          <input v-model="form.account" />
        </label>
        <label>
          <span>Digits</span>
          <input v-model.number="form.digits" type="number" min="6" />
        </label>
        <label>
          <span>Period</span>
          <input v-model.number="form.period" type="number" min="15" />
        </label>
      </div>

      <label>
        <span>{{ secretLabel }}</span>
        <input v-model="form.secret" type="password" required />
      </label>
      <label>
        <span>Tags</span>
        <input v-model="form.tags" placeholder="work,personal" />
      </label>
      <label>
        <span>Notes</span>
        <textarea v-model="form.notes"></textarea>
      </label>

      <footer class="modal-actions">
        <button type="button" class="quiet" @click="$emit('close')">Cancel</button>
        <button :disabled="busy">{{ mode === "add" ? "Save" : "Update" }}</button>
      </footer>
    </form>
  </div>
</template>
