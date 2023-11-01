<template>
  <button :type="btnType" class="bg-green-500 p-2 rounded-md text-white hover:bg-green-800"
  @click="$emit('handleClick')">
    {{name}}
  </button>
</template>


<script setup>
defineProps({
    name: String,
    btnType: String,
})

defineEmits(['handleClick'])
</script>