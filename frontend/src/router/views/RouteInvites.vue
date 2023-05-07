<script setup lang='ts'>
import { IconCheckCircleBold, IconClockCountdownBold } from '@iconify-prerendered/vue-ph'
import Pending from '../../components/invites/Pending.vue'
import Redeemed from '../../components/invites/Redeemed.vue'
import { useToast } from '../../store/toast'

const toast = useToast()
</script>

<template>
  <div>
    <div class="page-title">
      <h1>Invite</h1>
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
          Redeemed
        </strong>
      </div>

      <div class="invite-list-items">
        <Redeemed v-for="one in 12" :key="one" :invite="{ key: 'cum' }" />
      </div>
    </div>
  </div>
</template>
