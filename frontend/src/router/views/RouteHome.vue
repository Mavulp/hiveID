<script setup lang='ts'>
import { IconPlusCircle } from '@iconify-prerendered/vue-ph'

/**
 * This is the wrapper component around each 'page'.
 *
 * In most cases you just create the layout and import components for each section here.
 * Not much logic is usually done here, except fetching data and/or displaying loading states etc
 */
</script>

<template>
  <div>
    <div class="page-title">
      <h1>Home</h1>
      <p>A platform for managing accounts across services from the Hivecom community. <br> Quickly sign-in to a service by clicking the item.</p>
    </div>
    <div class="home-services">
      <div v-for="item in 5" class="service" data-title-top="Sign to Service">
        <div class="service-logo">
          <img src="https://i.imgur.com/wcV1EW4.png" alt=" ">
        </div>
        <span>APirateHat</span>
      </div>

      <RouterLink :to="{ name: 'RouteServices' }" class="service add">
        <div class="service-logo">
          <IconPlusCircle />
        </div>

        <span>New Service</span>
      </RouterLink>
    </div>
  </div>
</template>
