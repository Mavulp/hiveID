<script setup lang='ts'>
import type { SerializedToast } from '../../store/toast'
defineProps<{ data: SerializedToast }>()
</script>

<template>
  <li>
    <div class="toast-item" :class="[`type-${data.type}`, { 'has-action': data.action }]">
      <p>{{ data.message }}</p>
      <div v-if="data.action" class="flex-wrap right">
        <button class="button btn-gray-dark" @click="data.action?.fn(data)">
          {{ data.action.label }}
        </button>
      </div>
    </div>
  </li>
</template>
