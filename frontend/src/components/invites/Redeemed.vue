<script setup lang='ts'>
const props = defineProps<{
  invite: any // TODO: use generared type
}>()

// This property disables the hover tooltip if user hovers the revoke button
</script>

<template>
  <div class="invite redeemed">
    <div class="invite-title">
      <span class="url">
        Used by <b>dolanske</b>
        (http://localhost:5173/invites/invite?=cum)
      </span>
      <!-- <div class="info">
        <span>
          Issued by <b>Jokler</b>
        </span>
        <div class="vertical-divider" />
        <span>
          Created 4 days ago
        </span>
      </div> -->
    </div>
  </div>
</template>
