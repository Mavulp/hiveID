<script setup lang='ts'>
import Sidebar from './components/navigation/Sidebar.vue'
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
  </div>
</template>
