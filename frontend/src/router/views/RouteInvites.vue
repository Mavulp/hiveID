<script setup lang='ts'>
import { IconCheckCircleBold, IconClockCountdownBold, IconUserPlusBold } from '@iconify-prerendered/vue-ph'
import { useClipboard } from '@vueuse/core'
import Pending from '../../components/invites/Pending.vue'
import Used from '../../components/invites/Used.vue'
import { useToast } from '../../store/toast'

const toast = useToast()
const { copy } = useClipboard()

function createInvite() {
  copy('shit')

  toast.push({
    type: 'success',
    message: 'Invite link copied to clipboard',
  }, true)
}
</script>

<template>
  <div class="invite-page">
    <div class="page-title">
      <div class="flex">
        <h1>Invites</h1>
        <button class="button btn-border btn-accent  btn-round" @click="createInvite()">
          <IconUserPlusBold />
          New Invite
        </button>
      </div>
      <p>Create and manage invite links to the authentication system.</p>
    </div>
    <!-- <hr> -->
    <div class="invite-list">
      <div class="list-title">
        <div class="title-icon pending">
          <IconClockCountdownBold />
        </div>
        <strong>
          Pending
        </strong>
        <div class="flex-1" />
        <span>2 Invites</span>
      </div>

      <div class="invite-list-items">
        <Pending v-for="one in 1" :key="one" :invite="{ key: 'cum' }" />
      </div>
    </div>

    <div class="invite-list">
      <div class="list-title">
        <div class="title-icon redeemed">
          <IconCheckCircleBold />
        </div>
        <strong>
          Used
        </strong>

        <div class="flex-1" />
        <span>10 Used Invites</span>
      </div>

      <div class="invite-list-items">
        <Used v-for="one in 12" :key="one" :invite="{ key: 'cum' }" />
      </div>
    </div>
  </div>
</template>
