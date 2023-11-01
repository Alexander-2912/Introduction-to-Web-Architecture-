<template>
  <h1>Leaderboard</h1>
  <div class="flex w-full items-center">
    <div class="mx-auto w-1/2">
      <DataTable class="display" :columns="columns" :data="data.data" :options="options"/>
    </div>
  </div>
</template>

<script setup>
import DataTable from "datatables.net-vue3";
import DataTablesCore from "datatables.net-dt";
import { useAxios } from "../composable/useAxios";
import { ref, onMounted } from "vue";

DataTable.use(DataTablesCore);
const data = ref([]);
const { tryFetch } = useAxios();

const columns = [
  { data: "username", title: "username" },
  { data: "count_tweet", title: "Tweet Count" },
];

const options = {
    paging: false,
    searching: false,
    details: false,
    info: false,
}

const handleFetch = async () => {
  const res = await tryFetch("/api/counts");
  data.value = res.data;
  console.log(data.value);
};

onMounted(() => {
  handleFetch();
});
</script>

<style>
@import "datatables.net-dt";
</style>
