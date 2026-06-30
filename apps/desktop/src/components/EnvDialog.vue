<script setup lang="ts">
import { reactive, watch } from "vue";
import type { EnvForm, SecretEntry } from "../types";
import { createEnvForm } from "../utils/entries";

const props = defineProps<{
  open: boolean;
  entry: SecretEntry | null;
  busy: boolean;
}>();

const emit = defineEmits<{
  (event: "close"): void;
  (event: "set-value", form: EnvForm): void;
  (event: "set-ref", form: EnvForm): void;
}>();

const form = reactive<EnvForm>(createEnvForm());

watch(
  () => [props.open, props.entry] as const,
  () => Object.assign(form, createEnvForm(props.entry ?? undefined)),
  { immediate: true },
);

function submit() {
  if (form.source === "secret-ref") {
    emit("set-ref", { ...form });
  } else {
    emit("set-value", { ...form });
  }
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="$emit('close')">
    <form class="modal" @submit.prevent="submit">
      <header class="modal-head">
        <h2>Add Env Key</h2>
        <button type="button" class="icon-button" title="Close" @click="$emit('close')">×</button>
      </header>

      <div class="grid">
        <label>
          <span>Project</span>
          <input v-model="form.project" required />
        </label>
        <label>
          <span>Profile</span>
          <input v-model="form.profile" required />
        </label>
        <label>
          <span>Key</span>
          <input v-model="form.key" required />
        </label>
        <label>
          <span>Source</span>
          <select v-model="form.source">
            <option value="literal">literal</option>
            <option value="secret-ref">secret-ref</option>
          </select>
        </label>
      </div>

      <label v-if="form.source === 'literal'">
        <span>Value</span>
        <input v-model="form.value" type="password" required />
      </label>

      <div v-else class="grid">
        <label>
          <span>Reference type</span>
          <select v-model="form.refKind">
            <option value="api-key">api-key</option>
            <option value="token">token</option>
          </select>
        </label>
        <label>
          <span>Secret name or id</span>
          <input v-model="form.secretName" required />
        </label>
      </div>

      <footer class="modal-actions">
        <button type="button" class="quiet" @click="$emit('close')">Cancel</button>
        <button :disabled="busy">Save</button>
      </footer>
    </form>
  </div>
</template>
