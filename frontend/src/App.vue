<script setup lang='ts'>
import Sidebar from './components/navigation/Sidebar.vue'
import ToastWrap from './components/toast/ToastWrap.vue'
</script>

<template>
  <div class="app">
    <Sidebar />
    <div class="router-wrap">
      <RouterView v-slot="{ Component }">
        <Transition name="fade" mode="out-in">
          <component :is="Component" />
        </Transition>
      </RouterView>
    </div>

    <ToastWrap />
  </div>
</template>
