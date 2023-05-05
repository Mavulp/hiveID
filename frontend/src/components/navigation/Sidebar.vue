<script setup lang='ts'>
import { IconCodeSimpleBold } from '@iconify-prerendered/vue-ph'
</script>

<template>
  <aside>
    <div class="logo" title="HIV ID">
      <img src="/icons/logo.svg" alt="">
    </div>
    <RouterLink class="router-link" :to="{ name: 'RouteHome' }">
      Home
    </RouterLink>
    <hr>
    <RouterLink class="router-link" :to="{ name: 'RouteServices' }">
      Services
    </RouterLink>
    <RouterLink class="router-link" :to="{ name: 'RoutePermissions' }">
      Permissions
    </RouterLink>
    <RouterLink class="router-link" :to="{ name: 'RouteInvites' }">
      Invites
    </RouterLink>
    <RouterLink class="router-link" :to="{ name: 'RouteLog' }">
      Audit Log
    </RouterLink>
    <hr>
    <div class="sidebar-user">
      <RouterLink :to="{ name: 'RouteAccount' }">
        <div class="user-initial">
          D
        </div>
        dolanske
      </RouterLink>
    </div>

    <div class="flex-1" />

    <p class="copyright">
      <IconCodeSimpleBold />
      Made by <a href="https://github.com/Mavulp" target="_blank">Mavulp</a> in 2023
    </p>
  </aside>
</template>
