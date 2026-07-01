<script setup>
defineProps({
  title: { type: String, default: '' },
  description: { type: String, default: '' },
  flush: { type: Boolean, default: false },
})
</script>

<template>
  <section class="section-block" :class="{ 'is-flush': flush }">
    <header v-if="title || $slots.actions" class="section-block-head">
      <div><h2 v-if="title">{{ title }}</h2><p v-if="description">{{ description }}</p></div>
      <div v-if="$slots.actions" class="section-block-actions"><slot name="actions" /></div>
    </header>
    <div class="section-block-body"><slot /></div>
  </section>
</template>
