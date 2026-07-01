<script setup>
import { computed } from 'vue'

const props = defineProps({
  status: { type: String, default: 'PENDING' },
  label: { type: String, default: '' },
  size: { type: String, default: 'default' },
})

const normalized = computed(() => {
  const status = String(props.status || 'PENDING').toUpperCase()
  if (['NORMAL', 'SUCCESS', 'SAFE'].includes(status)) return 'normal'
  if (['TOLERATED', 'NORMAL_WITH_TOLERANCE', 'LOW_RISK'].includes(status)) return 'tolerated'
  if (['UNKNOWN', 'UNKNOWN_VALIDITY', 'REVIEW'].includes(status)) return 'unknown'
  if (['ANOMALY', 'ERROR', 'FAILED', 'HIGH_RISK'].includes(status)) return 'anomaly'
  if (['RUNNING', 'LOADING'].includes(status)) return 'running'
  return 'pending'
})

const defaultLabel = computed(() => ({
  normal: 'NORMAL',
  tolerated: 'TOLERATED',
  unknown: 'UNKNOWN',
  anomaly: 'ANOMALY',
  running: 'RUNNING',
  pending: 'PENDING',
})[normalized.value])
</script>

<template>
  <span class="risk-status" :class="[`is-${normalized}`, `is-${size}`]">
    <i></i>{{ label || defaultLabel }}
  </span>
</template>
