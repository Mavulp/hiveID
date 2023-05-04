<script setup lang='ts'>
import { useToast } from '../../store/toast'
import ToastItem from './ToastItem.vue'
const toasts = useToast()
</script>

<template>
  <div class="toasts-wrap">
    <ul>
      <TransitionGroup name="tab">
        <ToastItem v-for="[, item] in toasts.items" :key="item._id" :data="item" />
      </TransitionGroup>
    </ul>
  </div>
</template>
