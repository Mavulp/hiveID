<script setup lang='ts'>
import type { SerializedToast } from '../../store/toast'

defineProps<{ data: SerializedToast }>()
</script>

<template>
  <li>
    <div class="toast-item" :class="[`type-${data.type}`, { 'has-action': data.action }]">
      <p v-html="data.message" />
      <div v-if="data.action" class="flex right">
        <button class="button btn-white btn-small" @click="data.action?.fn(data)">
          {{ data.action.label }}
        </button>
      </div>
    </div>
  </li>
</template>
