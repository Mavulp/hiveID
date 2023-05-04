<script setup lang='ts'>
import { flip, offset, shift, size, useFloating } from '@floating-ui/vue'
import { onClickOutside } from '@vueuse/core'
import { isArray } from 'lodash-es'
import { computed, ref } from 'vue'

type Options = Record<string, string>
type Value = string | string[] | null

const props = defineProps<{
  label?: string
  placeholder?: string
  options: Options
  modelValue: string | string[] | null | undefined
  multiple?: boolean
  cantclear?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: Value): void
}>()

const open = ref(false)
const anchor = ref()
const dropdown = ref()

onClickOutside(anchor, () => {
  open.value = false
})

// Render text within the button
const buttonText = computed(() => {
  if (!props.modelValue || props.modelValue.length === 0)
    return props.placeholder ?? 'Select'

  if (isArray(props.modelValue)) {
    return Object.entries(props.options)
      .filter(([key]) => props.modelValue?.includes(key))
      .map(([_, value]) => value).join(', ')
  }

  return props.options[props.modelValue]
})

// Select value
function setValue(value: string) {
  // Multiple
  if (props.multiple && isArray(props.modelValue)) {
    if (props.modelValue.includes(value)) {
      // Clearing
      if (props.cantclear && props.modelValue.length === 1)
        return

      const filtered = props.modelValue.filter(s => s !== value)
      emit('update:modelValue', filtered)
    }
    else {
      // Setting
      emit('update:modelValue', [...props.modelValue, value])
    }
  }
  else {
    // Single
    if (props.modelValue && props.modelValue === value) {
      // Clearing
      if (props.cantclear)
        return
      emit('update:modelValue', null)
    }
    else {
      // Setting
      emit('update:modelValue', value)
      // Only close if you multiple=false and you just set an item
      open.value = false
    }
  }
}

// FLoating
const { x, y, strategy } = useFloating(anchor, dropdown, {
  placement: 'bottom-start',
  strategy: 'fixed',
  middleware: [shift(), flip(), size({
    apply({ availableHeight, elements }) {
      elements.floating.style.maxHeight = `${availableHeight - 15}px`
    },
  }), offset(8)],
})

const computedPosition = computed(() => ({
  position: strategy.value,
  left: `${x.value ?? 0}px`,
  top: `${y.value ?? 0}px`,
}))
</script>

<template>
  <div ref="anchor" class="form-item form-select">
    <label v-if="label">{{ label }} </label>

    <button
      class="select-button"
      :class="{ 'is-empty': !props.modelValue || props.modelValue.length === 0 }"
      @click="open = !open"
    >
      {{ buttonText }}
      <Icon :icon="open ? 'ph:caret-up' : 'ph:caret-down'" />
    </button>

    <div v-if="open" ref="dropdown" class="dropdown" :style="computedPosition">
      <button
        v-for="(item, value) in props.options"
        :key="value"
        class="button btn-small btn-full"
        :class="{ 'is-selected': props.modelValue === value || props.modelValue?.includes(value) }"
        @click="setValue(value)"
      >
        {{ item }}
      </button>
    </div>
  </div>
</template>
