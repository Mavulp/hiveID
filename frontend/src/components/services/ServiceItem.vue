<script setup lang='ts'>
import { IconCaretDown, IconCaretUp, IconListBold } from '@iconify-prerendered/vue-ph'
import { ref } from 'vue'
import Details from '../common/Details.vue'

const open = ref(false)
</script>

<template>
  <div class="service" :class="{ 'is-active': open }">
    <Details @open="(v) => open = v">
      <template #header="{ toggle }">
        <button class="service-header" @click.self="toggle">
          <div class="title">
            <h2>Quotes</h2>
            <p>A website that keeps quotes with or without context </p>
          </div>
          <p>https://quotes.hivecom.net/authorize</p>

          <div class="buttons">
            <button class="button btn-icon btn-gray">
              <IconListBold />
            </button>
            <button class="button btn-icon btn-gray caret" @click="toggle">
              <IconCaretUp v-if="open" />
              <IconCaretDown v-else />
            </button>
          </div>
        </button>
      </template>
      <template #content="{ open }">
        <div>
          <p>piss off</p>
        </div>
      </template>
    </Details>
  </div>
</template>
