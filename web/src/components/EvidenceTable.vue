<script setup>
defineProps({
  data: { type: Array, default: () => [] },
  height: { type: [String, Number], default: 400 },
  emptyText: { type: String, default: '暂无证据记录' },
  rowClassName: { type: [String, Function], default: '' },
})
</script>

<template>
  <div class="data-table evidence-table">
    <el-table
      :data="data"
      :height="height"
      stripe
      :empty-text="emptyText"
      :row-class-name="rowClassName"
    >
      <slot />
    </el-table>
  </div>
</template>
