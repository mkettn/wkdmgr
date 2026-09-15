<script setup>
import { ref } from 'vue'
import { uploadKey } from '../api.js'

const props = defineProps({
  addresses: { type: Array, required: true },
})
const emit = defineEmits(['uploaded'])

const selectedAddress = ref('')
const keyText = ref('')
const submitting = ref(false)
const errorMessage = ref('')
const successMessage = ref('')

async function onSubmit() {
  errorMessage.value = ''
  successMessage.value = ''
  if (!selectedAddress.value || !keyText.value.trim()) {
    errorMessage.value = 'choose an address and paste a key first'
    return
  }
  submitting.value = true
  try {
    const result = await uploadKey(selectedAddress.value, keyText.value.trim())
    successMessage.value = `published for ${result.address} (fingerprint ${result.fingerprint})`
    keyText.value = ''
    emit('uploaded')
  } catch (err) {
    errorMessage.value = err.message || 'upload failed'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <form class="upload-form" @submit.prevent="onSubmit">
    <label class="field">
      <span class="field-label">Address</span>
      <select v-model="selectedAddress" required>
        <option value="" disabled>Select an address&hellip;</option>
        <option v-for="address in props.addresses" :key="address" :value="address">
          {{ address }}
        </option>
      </select>
    </label>

    <label class="field">
      <span class="field-label">Public key (ASCII-armored or base64)</span>
      <textarea
        v-model="keyText"
        rows="8"
        placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&hellip;"
        required
      ></textarea>
    </label>

    <button type="submit" :disabled="submitting">
      {{ submitting ? 'Publishing…' : 'Publish key' }}
    </button>

    <p v-if="errorMessage" class="message message--error">{{ errorMessage }}</p>
    <p v-if="successMessage" class="message message--success">{{ successMessage }}</p>
  </form>
</template>

<style scoped>
.upload-form {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

.field-label {
  font-size: 0.8rem;
  color: var(--muted);
}

select,
textarea {
  font: inherit;
  font-size: 0.85rem;
  padding: 0.5rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
}

textarea {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  resize: vertical;
}

button {
  align-self: flex-start;
  font: inherit;
  font-size: 0.85rem;
  font-weight: 600;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 6px;
  background: var(--accent);
  color: var(--accent-contrast);
  cursor: pointer;
}

button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.message {
  margin: 0;
  font-size: 0.82rem;
}

.message--error {
  color: var(--danger);
}

.message--success {
  color: var(--accent);
}
</style>
