<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'
import { getVersion } from '@tauri-apps/api/app'
import { check, downloadAndInstall } from '@src/tauri/updater'

const store = useVpnStore()
const osPlatform = ref<'windows' | 'linux' | 'macos' | 'unknown'>('unknown')
const selected = ref<'systemproxy' | 'tun'>(store.routingMode)
const appVersion = ref<string>('')

const updateState = ref<'idle' | 'checking' | 'available' | 'downloading' | 'installed' | 'none' | 'error'>('idle')
const updateMessage = ref<string>('')
const updateVersion = ref<string>('')

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
    const res = await check()
    
    console.log('[UPDATER] Check result:', res)

    if (!res) {
      updateState.value = 'error'
      updateMessage.value = 'Failed to check for updates (web mode?).'
      console.log('[UPDATER] No result from backend')
      return
    }

    if (!res.available) {
      updateState.value = 'none'
      updateMessage.value = `No updates available (current: v${res.current_version}).`
      console.log('[UPDATER] No updates available')
      return
    }

    // Update is available
    updateState.value = 'available'
    updateVersion.value = res.version || ''
    updateMessage.value = `Update available: v${res.version} (current v${res.current_version}). Click "Install Update" to download and install.`
    console.log('[UPDATER] Update available:', res.version)
  } catch (e: any) {
    console.error('[UPDATER] Check failed:', e)
    updateState.value = 'error'
    updateMessage.value = `Update check failed: ${e?.message ?? String(e)}`
  }
}

async function installUpdate() {
  updateState.value = 'downloading'
  updateMessage.value = `Downloading update v${updateVersion.value}...`

  try {
    console.log('[UPDATER] Starting download and install...')
    await downloadAndInstall()
    
    updateState.value = 'installed'
    updateMessage.value = 'Update installed successfully! Please restart the application to apply the update.'
    console.log('[UPDATER] Update installed, restart required')
  } catch (e: any) {
    console.error('[UPDATER] Install failed:', e)
    updateState.value = 'error'
    updateMessage.value = `Update installation failed: ${e?.message ?? String(e)}`
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
        <div class="flex gap-2">
          <button
            v-if="updateState === 'available'"
            type="button"
            class="px-3 py-2 rounded-md bg-green-600 text-white text-sm hover:bg-green-700"
            @click="installUpdate"
          >
            Install Update
          </button>
          <button
            type="button"
            class="px-3 py-2 rounded-md bg-gray-900 text-white text-sm hover:bg-gray-800 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-white"
            :disabled="updateState === 'checking' || updateState === 'downloading' || updateState === 'installed'"
            @click="checkForUpdates"
          >
            <span v-if="updateState === 'checking'">Checking...</span>
            <span v-else-if="updateState === 'downloading'">Downloading...</span>
            <span v-else>Check updates</span>
          </button>
        </div>
      </div>
      <div v-if="updateMessage" class="mt-2 text-xs" :class="updateState === 'error' ? 'text-red-600 dark:text-red-400' : updateState === 'installed' ? 'text-green-600 dark:text-green-400' : 'text-gray-600 dark:text-gray-400'">
        {{ updateMessage }}
      </div>
    </div>
  </div>
</template>


