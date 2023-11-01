<template>
    <div class="bg-gray-200 mt-3 p-5 rounded-sm space-y-5">
        <p>{{ props.content }}</p>
        <div class="user">
            <span class="text-xs">{{ props.user }}</span>
        </div>
    </div>
</template>

<script setup>
const props = defineProps(['content', 'user'])

</script>