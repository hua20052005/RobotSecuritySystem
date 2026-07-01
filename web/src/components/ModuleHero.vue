<script setup>
defineProps({
  objective: { type: String, required: true },
  input: { type: String, required: true },
  output: { type: String, required: true },
  scenario: { type: String, default: '' },
})
</script>

<template>
  <section class="module-hero">
    <div><span>检测目标</span><strong>{{ objective }}</strong></div>
    <div><span>输入</span><strong>{{ input }}</strong></div>
    <div><span>输出</span><strong>{{ output }}</strong></div>
    <div v-if="scenario"><span>适用场景</span><strong>{{ scenario }}</strong></div>
  </section>
</template>
