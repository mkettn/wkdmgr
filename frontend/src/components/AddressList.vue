<script setup lang="ts">
import { computed } from 'vue'
import type { KeyResponseItem } from '../api'

const props = defineProps<{
  addresses: string[]
  keys: KeyResponseItem[]
}>()

type Status = 'published' | 'revoked' | 'expired' | 'no key'

const statusLabel: Record<Status, string> = {
  published: 'published',
  revoked: 'revoked',
  expired: 'expired',
  'no key': 'no key',
}

// A key row existing is not the same as WKD actually serving it: a
// revoked or expired key stays listed (so its owner can see and manage
// it) but wkdmgr-query 404s it exactly like "no key published" -- so
// this must not say "published" for either, or the badge asserts the
// opposite of what a lookup would actually return.
function statusFor(key: KeyResponseItem | undefined): Status {
  if (!key) return 'no key'
  if (key.revoked) return 'revoked'
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) return 'expired'
  return 'published'
}

const rows = computed(() =>
  props.addresses.map((address) => {
    const key = props.keys.find((k) => k.address.toLowerCase() === address.toLowerCase())
    return { address, status: statusFor(key) }
  }),
)
</script>

<template>
  <p v-if="rows.length === 0" class="empty">
    The identity backend reports no addresses for your account.
  </p>
  <ul v-else class="address-list">
    <li v-for="row in rows" :key="row.address" class="address-row">
      <span class="address">{{ row.address }}</span>
      <span :class="['badge', `badge--${row.status.replace(' ', '-')}`]">
        {{ statusLabel[row.status] }}
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

.badge--revoked,
.badge--expired {
  background: color-mix(in srgb, var(--danger) 18%, transparent);
  color: var(--danger);
}

.badge--no-key {
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--border);
}
</style>
