<template>
  <div class="flex flex-col items-center justify-center space-y-6 py-8">
    <!-- Connection Status Icon -->
    <div class="flex items-center justify-center w-16 h-16 bg-green-100 dark:bg-green-900/30 rounded-full">
      <svg class="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
      </svg>
    </div>

    <!-- Status Text -->
    <div class="text-center">
      <h3 class="text-xl font-semibold text-gray-900 dark:text-gray-100">Connected</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
        Connected to {{ connectedName }}
      </p>
    </div>

    <!-- IP and Country Info -->
    <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700 p-4 w-full max-w-sm">
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-3">
          <div class="w-8 h-8 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center">
            <svg class="w-4 h-4 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9"></path>
            </svg>
          </div>
          <div>
            <div class="text-sm font-medium text-gray-900 dark:text-gray-100">{{ store.ip || 'Loading...' }}</div>
            <div class="text-xs text-gray-600 dark:text-gray-400">{{ store.country || 'Unknown' }}</div>
          </div>
        </div>
        <div class="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
      </div>
    </div>

    <!-- Add Config Button -->
    <button 
      @click="store.showConfigInput()"
      class="flex items-center space-x-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-neutral-700 hover:bg-gray-200 dark:hover:bg-neutral-600 active:bg-gray-300 dark:active:bg-neutral-500 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
      :disabled="store.isBusy"
    >
      <span v-if="store.isBusy" class="w-4 h-4 border-2 border-gray-600 dark:border-gray-300 border-t-transparent rounded-full animate-spin"></span>
      <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
      </svg>
      <span>Add Config</span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { useVpnStore } from '@src/stores/vpnStore'
import { computed } from 'vue'

const store = useVpnStore()
const connectedName = computed(() => {
  const cfg = store.parsedConfig
  if (cfg?.name?.trim()) return cfg.name
  if (cfg?.server && cfg?.port) return `${cfg.server}:${cfg.port}`
  return store.ip || 'server'
})
</script>
