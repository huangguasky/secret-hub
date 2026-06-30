<script setup lang="ts">
import { computed, reactive, watch } from "vue";
import { FileCode2, Trash2 } from "lucide-vue-next";
import type { EnvForm, SecretEntry } from "../types";
import { createEnvForm, envVariables, textField } from "../utils/entries";

const props = defineProps<{
  entry: SecretEntry;
  rendered: string;
  busy: boolean;
  showValues: boolean;
}>();

const emit = defineEmits<{
  (event: "set-value", form: EnvForm): void;
  (event: "set-ref", form: EnvForm): void;
  (event: "remove", key: string): void;
  (event: "render", project: string, profile: string): void;
}>();

const form = reactive<EnvForm>(createEnvForm(props.entry));
const variables = computed(() => envVariables(props.entry));

watch(
  () => props.entry.id,
  () => Object.assign(form, createEnvForm(props.entry)),
);

function submit() {
  if (form.source === "secret-ref") {
    emit("set-ref", { ...form });
  } else {
    emit("set-value", { ...form });
  }
}

function valueText(variable: (typeof variables.value)[number]): string {
  if (variable.value.source === "secret-ref") {
    return `<ref:${variable.value.kind}:${variable.value.name}>`;
  }
  return props.showValues ? variable.value.value : "********";
}
</script>

<template>
  <section class="panel compact env-detail">
    <div class="section-head">
      <h2>{{ textField(entry, "project") }}/{{ textField(entry, "profile") }}</h2>
      <button
        class="with-icon"
        :disabled="busy"
        @click="$emit('render', textField(entry, 'project'), textField(entry, 'profile'))"
      >
        <FileCode2 :size="17" />
        Render
      </button>
    </div>

    <div class="env-table">
      <div class="env-row head">
        <span>Key</span>
        <span>Value</span>
        <span></span>
      </div>
      <div v-for="variable in variables" :key="variable.key" class="env-row">
        <strong>{{ variable.key }}</strong>
        <code>{{ valueText(variable) }}</code>
        <button class="icon-button danger" title="Remove" :disabled="busy" @click="$emit('remove', variable.key)">
          <Trash2 :size="16" />
        </button>
      </div>
    </div>

    <form class="env-editor" @submit.prevent="submit">
      <div class="grid">
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

      <div v-if="form.source === 'literal'" class="grid">
        <label>
          <span>Value</span>
          <input v-model="form.value" type="password" required />
        </label>
      </div>

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

      <button :disabled="busy">Set Env Key</button>
    </form>

    <pre v-if="rendered">{{ rendered }}</pre>
  </section>
</template>
