<script setup lang="ts">
import { computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()

const configs = computed(() => store.configs)

// Проверяем, какой конфиг сейчас активен
function isActiveConfig(config: any) {
  return store.parsedConfig && 
         store.parsedConfig.server === config.server && 
         store.parsedConfig.port === config.port && 
         store.parsedConfig.proxy_type === config.proxy_type
}

// Проверяем, подключены ли мы к этому конфигу
function isConnectedToConfig(config: any) {
  return isActiveConfig(config) && store.status === 'connected'
}

// Проверяем, подключаемся ли мы к этому конфигу
function isConnectingToConfig(config: any) {
  return isActiveConfig(config) && store.status === 'connecting'
}

async function connectToConfig(config: any) {
  // Устанавливаем конфиг и сразу подключаемся
  store.parsedConfig = config
  store.rawConfig = store.configToString(config)
  await store.connect()
}

async function disconnectFromConfig() {
  await store.disconnect()
}

function confirmRemove(config: any) {
  const ok = window.confirm('Are you sure you want to delete this configuration?')
  if (ok) {
    store.removeConfig(config)
  }
}

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
    
    <div class="max-h-48 sm:max-h-56 md:max-h-64 overflow-y-auto nice-scroll">
      <div v-if="configs.length === 0" class="p-4 text-center text-gray-500 dark:text-gray-400">
        No configs saved yet
      </div>
      
      <div v-else class="divide-y divide-gray-200/60 dark:divide-neutral-700">
        <div 
          v-for="config in configs" 
          :key="`${config.server}-${config.port}-${config.proxy_type}`"
          class="p-3 hover:bg-gray-50 dark:hover:bg-neutral-700/50 transition-colors"
          :class="{
            'bg-green-50 dark:bg-green-900/20 border-l-4 border-green-500': isConnectedToConfig(config),
            'bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500': isConnectingToConfig(config),
            'bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-500': isActiveConfig(config) && !isConnectedToConfig(config) && !isConnectingToConfig(config)
          }"
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
              <!-- Кнопка подключения/отключения -->
              <button 
                v-if="isConnectedToConfig(config)"
                @click="disconnectFromConfig()"
                :disabled="store.isBusy"
                class="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-700 active:bg-red-800 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-1.5 text-sm"
                title="Disconnect"
              >
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
                Disconnect
              </button>
              
              <button 
                v-else-if="isConnectingToConfig(config)"
                disabled
                class="px-3 py-1.5 rounded-md bg-yellow-600 text-white cursor-not-allowed transition-all duration-200 flex items-center gap-1.5 text-sm"
                title="Connecting..."
              >
                <span class="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                Connecting...
              </button>
              
              <button 
                v-else
                @click="connectToConfig(config)"
                :disabled="store.isBusy"
                class="px-3 py-1.5 rounded-md bg-green-600 hover:bg-green-700 active:bg-green-800 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-1.5 text-sm"
                title="Connect"
              >
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                </svg>
                Connect
              </button>
              
              
              <!-- Кнопка удаления конфига -->
              <button 
                @click="confirmRemove(config)"
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
