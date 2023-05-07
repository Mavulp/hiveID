<script setup lang='ts'>
import { useClipboard } from '@vueuse/core'
import { computed, ref } from 'vue'
import { useToast } from '../../store/toast'

const props = defineProps<{
  invite: any // TODO: use generared type
}>()

// This property disables the hover tooltip if user hovers the revoke button
const hovering = ref(false)

const toast = useToast()
const { copy } = useClipboard()

const url = computed(() => `${window.location}/invite?=${props.invite.key}`)

function copyLink() {
  copy(url.value)
    .then(() => {
      toast.push({
        type: 'success',
        message: 'Invite link copied to clipboard.',
      })
    })
    .catch(() => {
      toast.push({
        type: 'error',
        message: `Please copy the link manually <br/> <b>${url.value}</b>`,
        action: {
          label: 'Close',
          fn: ({ _id }) => toast.del(_id),
        },
      }, true)
    })
}

function revoke() {
  console.log('renove')
}
</script>

<template>
  <div class="invite" :data-title-left="hovering ? null : 'Copy Invite Link'" @click="copyLink">
    <div class="invite-title">
      <span class="url">v-cv_rMYQtC5j4UaXr5aew</span>
      <div class="info">
        <span>
          Issued by <b>dolanske</b>
        </span>
        <div class="vertical-divider" />
        <span>
          Created 4 days ago
        </span>
      </div>
    </div>
    <button
      class="button btn-accent"
      @click="revoke()"
      @mouseenter="hovering = true"
      @mouseleave="hovering = false"
    >
      Revoke
    </button>
  </div>
</template>
