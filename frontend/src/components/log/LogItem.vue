<script setup lang='ts'>
type LogType = 'delete-invite' | 'consume-invite' | 'create-invite' | 'permission' | 'service-settings'

interface LogItem {
  user: string
  type: LogType
  key?: string
  items?: LogItem[]
}

const props = defineProps<{
  data: LogItem
}>()

const language: Record<LogType, string> = {
  'consume-invite': 'consumed an invite',
  'delete-invite': 'deleted an invite',
  'create-invite': 'created an invite',
  'permission': 'changed user permission(s)',
  'service-settings': 'update service settings for',
}
</script>

<template>
  <div class="audit-item">
    <div class="item-header">
      <div class="user">
        <div class="user-initial gray">
          {{ props.data.user.substring(0, 1) }}
        </div>
        <strong>{{ props.data.user }}</strong>
      </div>
      <p>{{ language[props.data.type] }}</p>
      <strong v-if="props.data.key">{{ props.data.key }}</strong>
      <!-- <div class="flex-1" /> -->
      <span class="timestamp">3 days ago</span>
    </div>

    <div v-if="props.data.type === 'permission'" class="item-body">
      <ul class="permission-body">
        <li>
          <strong>Jokler</strong>
          <ul class="permission-add">
            <li class="tag tag-green">
              <!-- <IconPlusBold /> -->
              +quotes/add-quote
            </li>
            <li class="tag tag-green">
              <!-- <IconPlusBold /> -->
              +quotes/edit-quote
            </li>
          </ul>
          <ul class="permission-remove">
            <li class="tag tag-red">
              <!-- <IconPlusBold /> -->
              +quotes/delete-quote
            </li>
          </ul>
        </li>
        <li>
          <strong>tmtu</strong>
          <ul class="permission-remove">
            <li class="tag tag-red">
              <!-- <IconMinusBold /> -->
              -hiveid/admin
            </li>
          </ul>
        </li>
      </ul>
    </div>
  </div>
</template>
