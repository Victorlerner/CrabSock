<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'
import { getVersion } from '@tauri-apps/api/app'
import { check } from '@src/tauri/updater'

const store = useVpnStore()
const osPlatform = ref<'windows' | 'linux' | 'macos' | 'unknown'>('unknown')
const selected = ref<'systemproxy' | 'tun'>(store.routingMode)
const appVersion = ref<string>('')

const updateState = ref<'idle' | 'checking' | 'available' | 'downloading' | 'installed' | 'none' | 'error'>('idle')
const updateMessage = ref<string>('')

function detectPlatform(): 'windows' | 'linux' | 'macos' | 'unknown' {
  const ua = navigator.userAgent.toLowerCase()
  if (ua.includes('windows')) return 'windows'
  if (ua.includes('mac os') || ua.includes('macintosh')) return 'macos'
  if (ua.includes('linux')) return 'linux'
  return 'unknown'
}

const options = computed(() => {
  if (osPlatform.value === 'macos') {
    return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  if (osPlatform.value === 'linux') {
    return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  if (osPlatform.value === 'windows') {
    return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
  }
  // Unknown: expose both to allow testing
  return [ { label: 'System Proxy', value: 'systemproxy' as const }, { label: 'TUN (Kernel)', value: 'tun' as const } ]
})

async function init() {
  osPlatform.value = detectPlatform()
  selected.value = store.routingMode
  // Keep local select in sync with store updates (e.g., after relaunch/elevation)
  watch(() => store.routingMode, (v) => { selected.value = v })

  try {
    appVersion.value = await getVersion()
  } catch {
    // ignore (e.g., running in pure web mode)
  }
}

async function onChange() {
  if ((osPlatform.value === 'windows' || osPlatform.value === 'linux') && selected.value === 'tun') {
    try {
      // Persist desired mode first so relaunched admin instance reads it
      await store.setRoutingMode('tun')

      const ok = await (await import('@tauri-apps/api/core')).invoke<boolean>('ensure_admin_for_tun')
      if (!ok) {
        store.addLog('info', osPlatform.value === 'windows'
          ? 'Elevation requested. Confirm UAC dialog; app will relaunch as admin.'
          : 'Attempting to set capabilities via pkexec/sudo; app will relaunch.', 'frontend')
        // Terminate current process to avoid double instances; elevated one will start
        await (await import('@tauri-apps/api/core')).invoke('exit_app')
        return
      }
    } catch (e) {
      // Roll back to System Proxy if elevation failed/cancelled
      await store.setRoutingMode('systemproxy')
      selected.value = 'systemproxy'
      store.addLog('error', `Failed to enable TUN permissions: ${e}`, 'frontend')
      return
    }
    return
  }
  await store.setRoutingMode(selected.value)
}

async function checkForUpdates() {
  updateMessage.value = ''
  updateState.value = 'checking'

  try {
    const res: any = await check()

    // plugin-updater v2: returns null if no update is available
    if (!res) {
      updateState.value = 'none'
      updateMessage.value = 'No updates available.'
      return
    }

    // Some versions may return an object with `available: boolean`
    if (typeof res.available === 'boolean' && !res.available) {
      updateState.value = 'none'
      updateMessage.value = 'No updates available.'
      return
    }

    updateState.value = 'available'
    updateMessage.value = `Update available${res.version ? `: v${res.version}` : ''}. Downloading...`

    updateState.value = 'downloading'
    if (typeof res.downloadAndInstall === 'function') {
      await res.downloadAndInstall()
    } else if (typeof res.download === 'function' && typeof res.install === 'function') {
      await res.download()
      await res.install()
    }

    updateState.value = 'installed'
    updateMessage.value = 'Update installed. Restart the app to apply it.'
  } catch (e: any) {
    updateState.value = 'error'
    updateMessage.value = `Update check failed: ${e?.message ?? String(e)}`
  }
}

onMounted(init)
</script>

<template>
  <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4 space-y-4">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium">Routing mode</div>
        <div class="text-xs text-gray-500 dark:text-gray-400">
          <span v-if="osPlatform==='macos'">macOS: System Proxy or TUN</span>
          <span v-else-if="osPlatform==='linux'">Linux: System Proxy or TUN</span>
          <span v-else>Windows: System Proxy by default</span>
        </div>
      </div>
      <select
        class="px-3 py-2 rounded-md bg-white dark:bg-neutral-700 border border-gray-300 dark:border-neutral-600 text-sm"
        v-model="selected"
        @change="onChange"
      >
        <option v-for="opt in options" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
      </select>
    </div>
    <div class="mt-3 text-xs text-gray-600 dark:text-gray-400 space-y-1">
      <div><strong>TUN mode</strong>: Captures all traffic, including UDP. May interrupt ongoing calls (VoIP) when connecting or switching.</div>
      <div><strong>System Proxy</strong>: Best for quickly opening resources in apps that honor system proxy (browsers, Postman). Does not affect UDP traffic.</div>
    </div>

    <div class="pt-2 border-t border-gray-200/60 dark:border-neutral-700">
      <div class="flex items-center justify-between gap-3">
        <div class="text-sm font-medium">
          App version
          <span v-if="appVersion" class="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">v{{ appVersion }}</span>
        </div>
        <button
          type="button"
          class="px-3 py-2 rounded-md bg-gray-900 text-white text-sm hover:bg-gray-800 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white"
          :disabled="updateState === 'checking' || updateState === 'downloading'"
          @click="checkForUpdates"
        >
          <span v-if="updateState === 'checking'">Checking...</span>
          <span v-else-if="updateState === 'downloading'">Updating...</span>
          <span v-else>Check updates</span>
        </button>
      </div>
      <div v-if="updateMessage" class="mt-2 text-xs text-gray-600 dark:text-gray-400">
        {{ updateMessage }}
      </div>
    </div>
  </div>
</template>


