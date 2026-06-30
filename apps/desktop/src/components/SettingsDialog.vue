<script setup lang="ts">
import { reactive } from "vue";

defineProps<{
  open: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  (event: "close"): void;
  (
    event: "set-password",
    value: {
      password: string;
      confirmPassword: string;
      sessionMinutes: number;
    },
  ): void;
}>();

const form = reactive({
  password: "",
  confirmPassword: "",
  sessionMinutes: 30,
});

function reset() {
  form.password = "";
  form.confirmPassword = "";
  form.sessionMinutes = 30;
}

function close() {
  reset();
  emit("close");
}

function submit() {
  emit("set-password", { ...form });
}
</script>

<template>
  <div v-if="open" class="modal-backdrop" @click.self="close">
    <form class="modal" @submit.prevent="submit">
      <header class="modal-head">
        <h2>Settings</h2>
        <button type="button" class="icon-button" title="Close" @click="close">×</button>
      </header>

      <section class="settings-section">
        <h3>Login Password</h3>
        <label>
          <span>New password</span>
          <input v-model="form.password" type="password" required />
        </label>
        <label>
          <span>Confirm password</span>
          <input v-model="form.confirmPassword" type="password" required />
        </label>
        <label>
          <span>Session minutes</span>
          <input v-model.number="form.sessionMinutes" type="number" min="1" required />
        </label>
      </section>

      <footer class="modal-actions">
        <button type="button" class="quiet" @click="close">Cancel</button>
        <button :disabled="busy">Save Password</button>
      </footer>
    </form>
  </div>
</template>
