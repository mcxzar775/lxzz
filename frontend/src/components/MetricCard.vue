<script setup lang="ts">
defineProps<{
  label: string
  value: string | number
  tone?: 'blue' | 'green' | 'amber' | 'red'
}>()
</script>

<template>
  <article class="metric-card" :data-tone="tone ?? 'blue'">
    <span class="metric-label">{{ label }}</span>
    <strong class="metric-value">{{ value }}</strong>
  </article>
</template>

