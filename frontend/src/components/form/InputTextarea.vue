<script setup lang='ts'>
import { computed, useAttrs } from 'vue'
import type { ErrorObject } from '@vuelidate/core'

type Value = string | number | undefined
const props = defineProps<{
  modelValue: Value
  label?: string
  err?: ErrorObject[]
  cls?: string
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: Value): void
}>()

const value = computed({
  get: () => props.modelValue,
  set: val => emit('update:modelValue', val),
})

const attrs = useAttrs()
const hasErr = computed(() => props.err && props.err.length > 0)
</script>

<template>
  <div class="form-item" :class="[{ 'has-input': props.modelValue }, props.cls]">
    <label v-if="label">{{ label }}</label>
    <textarea v-model="value" v-bind="attrs" />

    <template v-if="hasErr">
      <p v-for="item in err" :key="item.$uid" class="form-error">
        {{ item.$message }}
      </p>
    </template>
  </div>
</template>
