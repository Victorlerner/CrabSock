<script setup lang="ts">
import { computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
const btnText = computed(() => {
  if (store.status === 'connecting') return 'Connecting...'
  if (store.status === 'connected') return 'Disconnect'
  return 'Connect'
})

async function onClick() {
  if (store.status === 'connected') {
    await store.disconnect()
  } else if (store.status === 'disconnected') {
    await store.connect()
  }
}
</script>

<template>
  <button
    class="px-4 py-2 rounded-md bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
    :disabled="store.status === 'connecting' || store.isBusy"
    @click="onClick"
  >
    <div v-if="store.status === 'connecting'" class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
    <svg v-else-if="store.status === 'connected'" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
    </svg>
    <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
    </svg>
    {{ btnText }}
  </button>
</template>


