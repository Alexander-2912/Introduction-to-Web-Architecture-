<template>
  <form @submit.prevent class="flex flex-col bg-gray-100 p-5 rounded-md w-100 space-y-3">
    <slot>
      <buttonC />
    </slot>
  </form>
</template>

<script setup>
import buttonC from "@/components/UI/button.vue";
</script>
