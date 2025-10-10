<script setup lang="ts">
import { computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()

const configs = computed(() => store.configs)

function getProxyIcon(proxyType: string) {
  switch (proxyType) {
    case 'Shadowsocks':
      return 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z'
    case 'VMess':
      return 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z'
    default:
      return 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z'
  }
}

function getProxyColor(proxyType: string) {
  switch (proxyType) {
    case 'Shadowsocks':
      return 'text-blue-600 dark:text-blue-400'
    case 'VMess':
      return 'text-purple-600 dark:text-purple-400'
    default:
      return 'text-gray-600 dark:text-gray-400'
  }
}
</script>

<template>
  <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700">
    <div class="p-4 border-b border-gray-200/60 dark:border-neutral-700">
      <h3 class="text-lg font-semibold">Saved Configs</h3>
    </div>
    
    <div class="max-h-64 overflow-y-auto">
      <div v-if="configs.length === 0" class="p-4 text-center text-gray-500 dark:text-gray-400">
        No configs saved yet
      </div>
      
      <div v-else class="divide-y divide-gray-200/60 dark:divide-neutral-700">
        <div 
          v-for="config in configs" 
          :key="`${config.server}-${config.port}-${config.proxy_type}`"
          class="p-3 hover:bg-gray-50 dark:hover:bg-neutral-700/50 transition-colors"
        >
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3 flex-1 min-w-0">
              <svg 
                class="w-5 h-5 flex-shrink-0" 
                :class="getProxyColor(config.proxy_type)"
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="getProxyIcon(config.proxy_type)"></path>
              </svg>
              
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-1">
                  <span class="font-medium text-gray-900 dark:text-gray-100 truncate">
                    {{ config.name }}
                  </span>
                  <span 
                    class="text-xs px-1.5 py-0.5 rounded"
                    :class="{
                      'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200': config.proxy_type === 'Shadowsocks',
                      'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-200': config.proxy_type === 'VMess',
                      'bg-gray-100 dark:bg-neutral-700 text-gray-600 dark:text-gray-300': true
                    }"
                  >
                    {{ config.proxy_type }}
                  </span>
                </div>
                <p class="text-sm text-gray-600 dark:text-gray-400">
                  {{ config.server }}:{{ config.port }}
                </p>
              </div>
            </div>
            
            <div class="flex items-center gap-1 ml-2">
              <button 
                @click="store.selectConfig(config)"
                class="p-1.5 rounded-md hover:bg-gray-100 dark:hover:bg-neutral-600 transition-colors"
                title="Select config"
              >
                <svg class="w-4 h-4 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                </svg>
              </button>
              
              <button 
                @click="store.removeConfig(config)"
                class="p-1.5 rounded-md hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
                title="Remove config"
              >
                <svg class="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
