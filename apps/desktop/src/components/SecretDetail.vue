<script setup lang="ts">
import { Pencil, Trash2 } from "lucide-vue-next";
import type { SecretEntry } from "../types";
import { arrayField, entryKind, secretField, textField } from "../utils/entries";

defineProps<{
  entry: SecretEntry;
  showValues: boolean;
  code: string;
  remainingSeconds: number;
  busy: boolean;
}>();

defineEmits<{
  (event: "edit"): void;
  (event: "delete"): void;
  (event: "copy-code"): void;
  (event: "copy-field", payload: { label: string; value: string }): void;
}>();

function displaySecret(entry: SecretEntry, showValues: boolean): string {
  const value = secretField(entry);
  if (!value) return "";
  return showValues ? value : "********";
}

function copyTitle(label: string): string {
  return `Copy ${label}`;
}
</script>

<template>
  <section class="panel compact">
    <div class="section-head">
      <h2>{{ entry.name }}</h2>
      <div class="actions">
        <button class="icon-button" title="Edit" :disabled="busy" @click="$emit('edit')">
          <Pencil :size="17" />
        </button>
        <button class="icon-button danger" title="Delete" :disabled="busy" @click="$emit('delete')">
          <Trash2 :size="17" />
        </button>
      </div>
    </div>

    <dl>
      <dt>Type</dt>
      <dd>{{ entryKind(entry) }}</dd>
      <template v-if="entryKind(entry) === 'password'">
        <dt>Username</dt>
        <dd>
          <button
            v-if="textField(entry, 'username')"
            class="copy-value-button"
            :title="copyTitle('username')"
            @click="$emit('copy-field', { label: 'Username', value: textField(entry, 'username') })"
          >
            {{ textField(entry, "username") }}
          </button>
          <template v-else>none</template>
        </dd>
        <dt>URL</dt>
        <dd>{{ textField(entry, "url") || "none" }}</dd>
      </template>
      <template v-if="entryKind(entry) === 'api-key'">
        <dt>Provider</dt>
        <dd>{{ textField(entry, "provider") || "none" }}</dd>
        <dt>Scopes</dt>
        <dd>{{ arrayField(entry, "scopes").join(", ") || "none" }}</dd>
      </template>
      <template v-if="entryKind(entry) === 'token'">
        <dt>Service</dt>
        <dd>{{ textField(entry, "service") || "none" }}</dd>
      </template>
      <template v-if="entryKind(entry) === 'totp'">
        <dt>Issuer</dt>
        <dd>{{ textField(entry, "issuer") || "none" }}</dd>
        <dt>Account</dt>
        <dd>{{ textField(entry, "account") || "none" }}</dd>
      </template>
      <dt>Secret</dt>
      <dd>
        <button
          v-if="showValues && secretField(entry)"
          class="copy-value-button"
          :title="copyTitle('secret')"
          @click="$emit('copy-field', { label: 'Secret', value: secretField(entry) })"
        >
          {{ displaySecret(entry, showValues) }}
        </button>
        <template v-else>{{ displaySecret(entry, showValues) || "none" }}</template>
      </dd>
      <dt>Tags</dt>
      <dd>{{ entry.tags.join(", ") || "none" }}</dd>
    </dl>

    <div v-if="entryKind(entry) === 'totp'" class="totp-code">
      <button class="code-button" :disabled="!code" title="Copy TOTP code" @click="$emit('copy-code')">
        <strong class="code">{{ code || "------" }}</strong>
      </button>
      <span class="countdown">{{ remainingSeconds }}s</span>
    </div>
  </section>
</template>
