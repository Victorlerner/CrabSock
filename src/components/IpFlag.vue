<script setup lang="ts">
import { onMounted } from 'vue'
import { useVpnStore } from '@src/stores/vpnStore'

const store = useVpnStore()
onMounted(() => store.refreshIp())
</script>

<template>
  <div class="text-sm text-gray-600 dark:text-gray-300">
    <span v-if="store.ip">{{ store.ip }}</span>
    <span v-else>—</span>
    <span v-if="store.country" class="ml-2">{{ store.country }}</span>
  </div>
</template>


