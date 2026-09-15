<script setup lang="ts">
import { ref } from 'vue'
import { deleteKey } from '../api'
import type { KeyResponseItem } from '../api'

const props = defineProps<{
  keys: KeyResponseItem[]
}>()
const emit = defineEmits<{
  deleted: []
}>()

const pendingId = ref<string | null>(null)
const errorMessage = ref('')

async function onDelete(id: string) {
  errorMessage.value = ''
  pendingId.value = id
  try {
    await deleteKey(id)
    emit('deleted')
  } catch (err) {
    errorMessage.value = err instanceof Error ? err.message : 'delete failed'
  } finally {
    pendingId.value = null
  }
}
</script>

<template>
  <p v-if="errorMessage" class="message message--error">{{ errorMessage }}</p>

  <p v-if="props.keys.length === 0" class="empty">No keys published yet.</p>
  <table v-else class="key-table">
    <thead>
      <tr>
        <th>Address</th>
        <th>Fingerprint</th>
        <th>Status</th>
        <th>Uploaded</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="key in props.keys" :key="key.id">
        <td class="mono">{{ key.address }}</td>
        <td class="mono fingerprint">{{ key.fingerprint }}</td>
        <td>
          <span :class="['badge', key.revoked ? 'badge--revoked' : 'badge--published']">
            {{ key.revoked ? 'revoked' : 'published' }}
          </span>
        </td>
        <td>{{ new Date(key.uploaded_at).toLocaleString() }}</td>
        <td class="actions">
          <button
            class="danger"
            :disabled="pendingId === key.id"
            @click="onDelete(key.id)"
          >
            {{ pendingId === key.id ? 'Removing…' : 'Remove' }}
          </button>
        </td>
      </tr>
    </tbody>
  </table>
</template>

<style scoped>
.empty {
  color: var(--muted);
  margin: 0;
}

.message--error {
  color: var(--danger);
  font-size: 0.82rem;
}

.key-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

.key-table th {
  text-align: left;
  font-size: 0.75rem;
  color: var(--muted);
  font-weight: 600;
  padding: 0.4rem 0.6rem;
  border-bottom: 1px solid var(--border);
}

.key-table td {
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  overflow-wrap: anywhere;
}

.fingerprint {
  font-size: 0.78rem;
  color: var(--muted);
}

.badge {
  font-size: 0.72rem;
  border-radius: 999px;
  padding: 0.15rem 0.55rem;
  white-space: nowrap;
}

.badge--published {
  background: color-mix(in srgb, var(--accent) 18%, transparent);
  color: var(--accent);
}

.badge--revoked {
  background: color-mix(in srgb, var(--danger) 18%, transparent);
  color: var(--danger);
}

.actions {
  text-align: right;
}

button.danger {
  font: inherit;
  font-size: 0.78rem;
  padding: 0.35rem 0.7rem;
  border: 1px solid var(--danger);
  border-radius: 6px;
  background: transparent;
  color: var(--danger);
  cursor: pointer;
}

button.danger:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
