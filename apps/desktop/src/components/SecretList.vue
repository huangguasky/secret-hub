<script setup lang="ts">
import { Plus } from "lucide-vue-next";
import type { SecretEntry } from "../types";
import { entryKind, entrySummary } from "../utils/entries";

defineProps<{
  entries: SecretEntry[];
  selectedId: string;
  canAdd: boolean;
  search: string;
}>();

defineEmits<{
  (event: "select", id: string): void;
  (event: "add"): void;
  (event: "update:search", value: string): void;
}>();
</script>

<template>
  <div class="list">
    <input
      class="search-input"
      :value="search"
      placeholder="Search"
      @input="$emit('update:search', ($event.target as HTMLInputElement).value)"
    />

    <button v-if="canAdd" class="add-row" title="Add secret" @click="$emit('add')">
      <Plus :size="18" />
      <span>Add</span>
    </button>

    <button
      v-for="entry in entries"
      :key="entry.id"
      :class="['row', { active: selectedId === entry.id }]"
      @click="$emit('select', entry.id)"
    >
      <span>{{ entry.name }}</span>
      <small>{{ entryKind(entry) }} · {{ entrySummary(entry) }}</small>
    </button>
  </div>
</template>
