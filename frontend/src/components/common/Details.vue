<script setup lang="ts">
import { IconCaretDown, IconCaretUp } from '@iconify-prerendered/vue-ph'
import { isNil } from 'lodash-es'
import { computed, nextTick, ref, useSlots, watch } from 'vue'

/* ---------------- TODO ---------------- */
// Try animating it

interface Props {
  open?: boolean
  header?: string
  unstyle?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  open: undefined,
})
const emit = defineEmits<{
  (e: 'open', state: boolean): void
}>()
const slots = useSlots()

const contentMaxHeight = ref(0)
const content = ref()
// const parent = ref()

const open = ref(false)
const isOpen = computed(() => {
  /* ---------------- TODO ---------------- */
  // Figure out how to control this component form the outside

  if (!isNil(props.open))
    return props.open

  return open.value
})

function toggle() {
  open.value = !open.value
}

watch(open, async (value) => {
  emit('open', value)

  if (value) {
    await nextTick()
    contentMaxHeight.value = content.value.scrollHeight
  }
})
</script>

<template>
  <div class="button-detail" :class="{ 'is-open': isOpen, 'unstyle': props.unstyle }">
    <template v-if="slots.header">
      <slot name="header" :open="open" :toggle="toggle" />
    </template>

    <button
      v-else-if="header"
      class="button-detail-header hover-block hover-full-size"
      :class="{ 'is-open': isOpen }"
      @click="open = !open"
    >
      <span v-html="header" />
      <IconCaretUp v-if="isOpen" />
      <IconCaretDown v-else />
    </button>

    <div ref="content" class="button-detail-content" :style="{ 'max-height': open ? `${contentMaxHeight}px` : 0 }">
      <slot v-if="slots.content" name="content" :toggle="toggle" :open="open" />
      <slot v-else :toggle="toggle" :open="open" />
    </div>
  </div>
</template>
