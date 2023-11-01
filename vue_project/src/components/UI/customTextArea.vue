<template>
  <div class="flex flex-col">
    <label for="Tweet">{{label}}</label>
    <textarea
      rows="5"
      cols="20"
      class="border-b-4 border-green-300 focus:outline-none focus:border-b-4 focus:border-green-800"
      :value="modelValue" @input="$emit('update:modelValue', $event.target.value)"
    ></textarea>
  </div>
</template>

<script setup>
defineProps(['label', 'modelValue'])
defineEmits(['update:modelValue'])
</script>
