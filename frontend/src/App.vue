<script setup lang='ts'>
import Sidebar from './components/navigation/Sidebar.vue'
</script>

<template>
  <div class="app">
    <Sidebar />
    <div class="router-wrap">
      <RouterView />
    </div>
  </div>
</template>
