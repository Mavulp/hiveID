<script setup lang='ts'>
import { ref } from 'vue'
import { IconPlusBold } from '@iconify-prerendered/vue-ph'
import ServiceItem from '../../components/services/ServiceItem.vue'
import InputText from '../../components/form/InputText.vue'

const search = ref<string>('')
</script>

<template>
  <div>
    <div class="page-title">
      <h1>Services</h1>
      <p>Create and manage your services.</p>
    </div>
    <div class="page-title-sticky">
      <InputText v-model="search" placeholder="Find a service..." />
      <button class="button btn-border btn-accent btn-large btn-round">
        <IconPlusBold />
        New Service
      </button>
    </div>

    <div class="service-list">
      <ServiceItem v-for="item in 10" :key="item" />
      <!-- <div class="service" /> -->
    </div>
  </div>
</template>
