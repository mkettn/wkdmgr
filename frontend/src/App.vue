<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getMe, listKeys, type KeyResponseItem } from './api'
import AddressList from './components/AddressList.vue'
import KeyUploadForm from './components/KeyUploadForm.vue'
import KeyList from './components/KeyList.vue'

const uid = ref<string | null>(null)
const addresses = ref<string[]>([])
const keys = ref<KeyResponseItem[]>([])
const loadError = ref('')
const loading = ref(true)

async function refreshKeys() {
  keys.value = await listKeys()
}

async function loadAll() {
  loading.value = true
  loadError.value = ''
  try {
    const me = await getMe()
    uid.value = me.uid
    addresses.value = me.addresses
    await refreshKeys()
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : 'failed to load'
  } finally {
    loading.value = false
  }
}

onMounted(loadAll)
</script>

<template>
  <div class="page">
    <header class="page-header">
      <h1>wkdmgr</h1>
      <span v-if="uid" class="uid-badge">{{ uid }}</span>
    </header>

    <p v-if="loading" class="status">Loading&hellip;</p>
    <p v-else-if="loadError" class="status status--error">{{ loadError }}</p>

    <main v-else class="layout">
      <section class="panel">
        <h2>Your addresses</h2>
        <AddressList :addresses="addresses" :keys="keys" />
      </section>

      <section class="panel">
        <h2>Publish a key</h2>
        <KeyUploadForm :addresses="addresses" @uploaded="refreshKeys" />
      </section>

      <section class="panel panel--wide">
        <h2>Published keys</h2>
        <KeyList :keys="keys" @deleted="refreshKeys" />
      </section>
    </main>
  </div>
</template>

<style>
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1a1d21;
  --muted: #6b7280;
  --border: #e2e5e9;
  --accent: #2f6feb;
  --accent-contrast: #ffffff;
  --danger: #c0392b;
  --panel-bg: #f8f9fb;
  --radius: 8px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a;
    --fg: #edeef0;
    --muted: #9aa1ab;
    --border: #2c2f36;
    --accent: #5b9bff;
    --accent-contrast: #0a1020;
    --danger: #ff6b5b;
    --panel-bg: #1b1e24;
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}
</style>

<style scoped>
.page {
  max-width: 960px;
  margin: 0 auto;
  padding: 2rem 1.25rem 4rem;
}

.page-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  margin-bottom: 1.5rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.4rem;
  letter-spacing: -0.01em;
}

.uid-badge {
  font-size: 0.85rem;
  color: var(--muted);
  background: var(--panel-bg);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.2rem 0.7rem;
}

.status {
  color: var(--muted);
}

.status--error {
  color: var(--danger);
}

.layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.25rem;
}

.panel {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--panel-bg);
  padding: 1.1rem 1.25rem 1.3rem;
}

.panel--wide {
  grid-column: 1 / -1;
}

.panel h2 {
  margin: 0 0 0.85rem;
  font-size: 1rem;
  font-weight: 600;
}

@media (max-width: 640px) {
  .layout {
    grid-template-columns: 1fr;
  }
}
</style>
