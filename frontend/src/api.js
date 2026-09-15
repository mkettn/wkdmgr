// Thin fetch wrapper for the wkdmgr-mgmt /api/* contract. This is the
// single place in the frontend that knows the API prefix and response
// shapes; components call these functions instead of calling fetch
// directly.
//
// Same-origin only: the SSO proxy sets the identity header on every
// request to this vhost (API calls included), so there is no auth logic
// here and no CORS handling needed.

const API_PREFIX = '/api'

class ApiError extends Error {
  constructor(status, code, message) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function request(path, options = {}) {
  const res = await fetch(`${API_PREFIX}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })

  if (res.status === 204) {
    return null
  }

  const isJson = (res.headers.get('content-type') || '').includes('application/json')
  const body = isJson ? await res.json().catch(() => null) : null

  if (!res.ok) {
    const code = body?.error || 'unknown_error'
    const message = body?.message || `request failed with status ${res.status}`
    throw new ApiError(res.status, code, message)
  }

  return body
}

/** GET /api/me -> { uid, addresses } */
export function getMe() {
  return request('/me')
}

/** GET /api/keys -> [{ id, address, domain, fingerprint, uploaded_at }] */
export function listKeys() {
  return request('/keys')
}

/**
 * POST /api/keys -> { id, address, domain, fingerprint }
 * `key` is ASCII-armored or base64 OpenPGP key material.
 */
export function uploadKey(address, key) {
  return request('/keys', {
    method: 'POST',
    body: JSON.stringify({ address, key }),
  })
}

/** DELETE /api/keys/:id */
export function deleteKey(id) {
  return request(`/keys/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export { ApiError }
