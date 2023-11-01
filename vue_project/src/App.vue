<script setup>
import {RouterView} from 'vue-router'
import navbar from '@/components/UI/navbar.vue';
</script>

<template>
  <navbar />
  <main>
    <RouterView />
  </main>
</template>
