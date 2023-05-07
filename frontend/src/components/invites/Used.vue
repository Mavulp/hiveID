<script setup lang='ts'>
import { IconCopyBold } from '@iconify-prerendered/vue-ph'
import { useClipboard } from '@vueuse/core'

const props = defineProps<{
  invite: any // TODO: use generared type
}>()

const { copy } = useClipboard()

function copyLink() {

}

// This property disables the hover tooltip if user hovers the revoke button
</script>

<template>
  <div class="invite redeemed">
    <div class="invite-title">
      <span class="url">
        dolanske
      </span>
      <div class="info">
        <span>
          Issued by <b>Jokler</b> 3 days ago
        </span>
        <div class="vertical-divider" />
        <div class="flex gap-5">
          <button class="button btn-small btn-icon btn-white" data-title-top="Copy" @click="copyLink()">
            <IconCopyBold />
          </button>
          <span>v-cv_rMYQtC5j4UaXr5aew</span>
        </div>
      </div>
    </div>
  </div>
</template>
