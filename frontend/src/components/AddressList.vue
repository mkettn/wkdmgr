<script setup>
import { computed } from 'vue'

const props = defineProps({
  addresses: { type: Array, required: true },
  keys: { type: Array, required: true },
})

const rows = computed(() =>
  props.addresses.map((address) => ({
    address,
    published: props.keys.some((k) => k.address.toLowerCase() === address.toLowerCase()),
  })),
)
</script>

<template>
  <p v-if="rows.length === 0" class="empty">
    The identity backend reports no addresses for your account.
  </p>
  <ul v-else class="address-list">
    <li v-for="row in rows" :key="row.address" class="address-row">
      <span class="address">{{ row.address }}</span>
      <span :class="['badge', row.published ? 'badge--published' : 'badge--unpublished']">
        {{ row.published ? 'published' : 'no key' }}
      </span>
    </li>
  </ul>
</template>

<style scoped>
.empty {
  color: var(--muted);
  margin: 0;
}

.address-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.address-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 0.7rem;
}

.address {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.85rem;
  overflow-wrap: anywhere;
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

.badge--unpublished {
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--border);
}
</style>
