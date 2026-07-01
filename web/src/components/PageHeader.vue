<script setup>
defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  serverStatus: { type: String, default: 'checking' },
  statusText: { type: String, default: '检测中' },
  apiHost: { type: String, default: '本地服务' },
})
</script>

<template>
  <header class="page-header">
    <div class="page-header-copy">
      <span class="page-kicker">安全分析工作台</span>
      <h1>{{ title }}</h1>
      <p v-if="description">{{ description }}</p>
    </div>
    <div class="page-header-actions">
      <div class="service-state" :class="`is-${serverStatus}`">
        <span class="service-dot"></span>
        <span>{{ statusText }}</span>
        <strong>{{ apiHost }}</strong>
      </div>
      <slot name="account" />
    </div>
  </header>
</template>
