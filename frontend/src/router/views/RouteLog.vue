<script setup lang='ts'>
import { useLocalStorage } from '@vueuse/core'
import { onBeforeMount, ref } from 'vue'
import InputText from '../../components/form/InputText.vue'
import LogItem from '../../components/log/LogItem.vue'

// TODO
// Save when user last visited this page
// Upon loading, when iterating over logs, insert a line marker to what new logs appeared since last visit

const lastLoginMarker = ref<number>()
const lastLogin = useLocalStorage<number>('audit-log-last-visit', null)
onBeforeMount(() => {
  if (lastLogin.value) {
    lastLoginMarker.value = lastLogin.value
    lastLogin.value = Date.now()
  }
})

const search = ref('')
</script>

<template>
  <div class="container c-mid">
    <div class="page-title">
      <h1>Adudit Log</h1>
      <p>Logs of all actions against the account database.</p>
    </div>
    <div class="page-title-sticky">
      <InputText v-model="search" placeholder="Search for user, time or action..." />
    </div>

    <div class="audit-log-list">
      <LogItem
        :data="{
          user: 'dolanske',
          type: 'delete-invite',
          key: 'v-cv_rMYQtC5j4UaXr5aew',
        }"
      />

      <LogItem
        :data="{
          user: 'dolanske',
          type: 'create-invite',
          key: 'v-cv_rMYQtC5j4UaXr5aew',
        }"
      />

      <LogItem
        :data="{
          user: 'dolanske',
          type: 'consume-invite',
          key: 'v-cv_rMYQtC5j4UaXr5aew',
        }"
      />

      <LogItem
        :data="{
          user: 'dolanske',
          type: 'permission',
        }"
      />

      <!-- TODO: Should link to the service as /services#service -->
      <LogItem
        :data="{
          user: 'dolanske',
          type: 'service-settings',
          key: 'xdd-dev',
        }"
      />
    </div>
  </div>
</template>
