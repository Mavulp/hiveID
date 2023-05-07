<script setup lang='ts'>
import { IconArrowUpBold } from '@iconify-prerendered/vue-ph'
import { useWindowScroll } from '@vueuse/core'
import Sidebar from './components/navigation/Sidebar.vue'
import ToastWrap from './components/toast/ToastWrap.vue'

const { y } = useWindowScroll()

function scrollUp() {
  window.scrollTo({
    top: 0,
    behavior: 'smooth',
  })
}
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

    <Transition mode="out-in" appear>
      <button v-if="y > 128" class="button btn-icon btn-small btn-accent btn-go-up" @click="scrollUp">
        <IconArrowUpBold />
      </button>
    </Transition>

    <ToastWrap />
  </div>
</template>

<style scoped lang="scss">
.btn-go-up {
  position: fixed;
  right: 26px;
  // transform: translateY(-50%);
  bottom: 80px;

  svg {
    font-size: 1.8rem !important;
  }
}
</style>
