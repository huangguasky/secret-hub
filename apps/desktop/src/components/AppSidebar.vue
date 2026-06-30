<script setup lang="ts">
import { KeyRound, Lock, RefreshCw, Settings } from "lucide-vue-next";
import type { DesktopStatus, EntryKind } from "../types";
import { kindFilters } from "../utils/entries";

defineProps<{
  status: DesktopStatus | null;
  filter: EntryKind;
  busy: boolean;
}>();

defineEmits<{
  (event: "update:filter", value: EntryKind): void;
  (event: "refresh"): void;
  (event: "lock"): void;
  (event: "settings"): void;
}>();
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <span class="mark" aria-hidden="true">
        <KeyRound :size="26" stroke-width="2.4" />
      </span>
      <div>
        <h1>Secret Hub</h1>
        <p>AuthMode: {{ status?.authMode ?? "not initialized" }}</p>
      </div>
    </div>

    <div class="status">
      <span :class="['dot', status?.loggedIn ? 'ok' : 'locked']"></span>
      <span>{{ status?.loggedIn ? "Unlocked" : "Locked" }}</span>
    </div>

    <nav class="filters">
      <button
        v-for="item in kindFilters"
        :key="item"
        :class="{ active: filter === item }"
        @click="$emit('update:filter', item)"
      >
        {{ item }}
      </button>
    </nav>

    <div class="sidebar-actions">
      <button
        v-if="status?.loggedIn"
        class="icon-button"
        title="Settings"
        :disabled="busy"
        @click="$emit('settings')"
      >
        <Settings :size="18" />
      </button>
      <button
        class="icon-button"
        title="Refresh"
        :disabled="busy"
        @click="$emit('refresh')"
      >
        <RefreshCw :size="18" />
      </button>
      <button
        v-if="status?.loggedIn"
        class="icon-button"
        title="Lock"
        :disabled="busy"
        @click="$emit('lock')"
      >
        <Lock :size="18" />
      </button>
    </div>
  </aside>
</template>
