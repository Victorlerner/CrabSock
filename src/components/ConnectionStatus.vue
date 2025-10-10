<script setup lang="ts">
import { computed } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()

const statusInfo = computed(() => {
  switch (store.status) {
    case 'connected':
      return {
        text: 'Connected',
        subtext: store.ip ? `${store.ip} (${store.country || 'Unknown'})` : 'Verifying connection...',
        color: 'text-green-600 dark:text-green-400',
        bgColor: 'bg-green-50 dark:bg-green-900/20',
        borderColor: 'border-green-200 dark:border-green-800',
        icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'
      }
    case 'connecting':
      return {
        text: 'Connecting...',
        subtext: 'Establishing connection',
        color: 'text-blue-600 dark:text-blue-400',
        bgColor: 'bg-blue-50 dark:bg-blue-900/20',
        borderColor: 'border-blue-200 dark:border-blue-800',
        icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z'
      }
    case 'disconnected':
      return {
        text: 'Disconnected',
        subtext: store.ip ? `Current IP: ${store.ip}` : 'Ready to connect',
        color: 'text-gray-600 dark:text-gray-400',
        bgColor: 'bg-gray-50 dark:bg-gray-900/20',
        borderColor: 'border-gray-200 dark:border-gray-800',
        icon: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'
      }
    default:
      return {
        text: 'Unknown',
        subtext: 'Unknown status',
        color: 'text-gray-600 dark:text-gray-400',
        bgColor: 'bg-gray-50 dark:bg-gray-900/20',
        borderColor: 'border-gray-200 dark:border-gray-800',
        icon: 'M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
      }
  }
})

const connectionDetails = computed(() => {
  if (!store.parsedConfig) return null
  
  return {
    server: store.parsedConfig.server,
    port: store.parsedConfig.port,
    method: store.parsedConfig.method || 'Unknown',
    type: store.parsedConfig.proxy_type
  }
})
</script>

<template>
  <div class="bg-white/70 dark:bg-neutral-800 rounded-xl border border-gray-200/60 dark:border-neutral-700">
    <div class="p-4">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold">Connection Status</h3>
        <div class="flex items-center gap-2">
          <div 
            class="w-3 h-3 rounded-full"
            :class="{
              'bg-green-500 animate-pulse': store.status === 'connected',
              'bg-blue-500 animate-pulse': store.status === 'connecting',
              'bg-gray-400': store.status === 'disconnected'
            }"
          ></div>
          <span class="text-sm text-gray-500 dark:text-gray-400">
            {{ store.status.toUpperCase() }}
          </span>
        </div>
      </div>

      <!-- Status Card -->
      <div 
        class="p-4 rounded-lg border"
        :class="[statusInfo.bgColor, statusInfo.borderColor]"
      >
        <div class="flex items-center gap-3">
          <svg 
            class="w-6 h-6"
            :class="statusInfo.color"
            fill="none" 
            stroke="currentColor" 
            viewBox="0 0 24 24"
          >
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="statusInfo.icon"></path>
          </svg>
          
          <div>
            <div 
              class="font-semibold"
              :class="statusInfo.color"
            >
              {{ statusInfo.text }}
            </div>
            <div class="text-sm text-gray-600 dark:text-gray-400">
              {{ statusInfo.subtext }}
            </div>
          </div>
        </div>
      </div>

      <!-- Connection Details -->
      <div v-if="connectionDetails && store.status === 'connected'" class="mt-4">
        <h4 class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Connection Details</h4>
        <div class="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span class="text-gray-500 dark:text-gray-400">Server:</span>
            <span class="ml-2 font-mono">{{ connectionDetails.server }}</span>
          </div>
          <div>
            <span class="text-gray-500 dark:text-gray-400">Port:</span>
            <span class="ml-2 font-mono">{{ connectionDetails.port }}</span>
          </div>
          <div>
            <span class="text-gray-500 dark:text-gray-400">Method:</span>
            <span class="ml-2 font-mono">{{ connectionDetails.method }}</span>
          </div>
          <div>
            <span class="text-gray-500 dark:text-gray-400">Type:</span>
            <span class="ml-2 font-mono">{{ connectionDetails.type }}</span>
          </div>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="mt-4 flex items-center gap-2">
        <button 
          v-if="store.status === 'connected'"
          @click="store.refreshIp()"
          class="px-3 py-1.5 text-sm rounded-md bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors"
        >
          Refresh IP
        </button>
        
        <button 
          @click="store.showLogs = !store.showLogs"
          class="px-3 py-1.5 text-sm rounded-md bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          {{ store.showLogs ? 'Hide Logs' : 'Show Logs' }}
        </button>
      </div>
    </div>
  </div>
</template>
