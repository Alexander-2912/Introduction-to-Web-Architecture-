<template>
  <div class="mx-40">
    <h1 class="text-2xl mt-4 mb-4">Halaman Home</h1>
    <formC class="bg-gray-300 rounded p-6">
        <div class="flex flex-col">
          <label for="Tweet">{{label}}</label>
          <textareaC label="Tweet" v-model="tweet" />
          {{ tweet }}
        <div class="flex gap-5 mt-7">
            <buttonC name="Submit" @handle-click="postContent"/>
            <buttonC name="Upload File" @handle-click="toggleModal"/>
        </div>
        </div>
    </formC>
    
    <card v-for="item in data" :key="item.id" :content="item.content"
    :user="item.user"/>

    <!-- <div class="modal" v-if="showModal">
      <div class="modal-container">
        <div class="flex">
          <label for="foto">Upload Foto</label>
          <input type="file" id="foto" class="inputFoto" />
        </div>
        <div class="flex">
          <label for="tweet">Tweet</label>
          <textarea rows="4" cols="10" id="tweet"></textarea>
        </div>
        <div class="button">
          <button>Submit</button>
          <button @click="toggleModal">Cancel</button>
        </div>
      </div>
    </div> -->

    <!-- modal baru -->
    <div v-if="showModal" class="w-full">
        <modalVue :isOpen="showModal" @close-modal="toggleModal"/>
    </div>
    <div>
      <buttonC @click="prevItem" :disabled="page == 1" name="Previous" class="mx-2">Prev</buttonC>
      <buttonC @click="nextItem" :disabled="page == total_page" name="Next" class="mx-2">Next</buttonC>
    </div>
</div>
</template>

<script setup>
import navbar from "@/components/UI/navbar.vue";
import formC from "@/components/UI/form.vue";
import card from "@/components/UI/card.vue";
import buttonC from "@/components/UI/button.vue";
import textareaC from "@/components/UI/customTextArea.vue";
import modalVue from "../components/UI/modals.vue";
import { ref, onMounted, watch } from "vue";
import { useAxios } from "../composable/useAxios";
import axios from 'axios'
import { useAuthStore } from "../stores/authStore";
import{ storeToRefs } from "pinia";

const page = ref(1)
const per_page = ref(2)
const total_page = ref()
const total_item = ref()

const prevItem = () => {
  page.value--
}

const nextItem = () => {
  page.value++
}

watch(page, (newPage) => {
  handleFetching(newPage, per_page.value)
})

const stores = useAuthStore()
const { accessToken, refreshToken, isAuthenticated } = storeToRefs(stores)

const data = ref([])

const {tryFetch} = useAxios()
const tweet = ref('');

const handleFetching = async (page, per_page) => {
  const result = await tryFetch('/api/tweets', page, per_page)
  console.log(result)
  data.value = result.data.data
  console.log(data.value)
  total_page.value = result.data.total_page
  total_item.value = result.data.total_item
}

const toggleClick = () => {
    console.log("print")
}

const postContent = async () => {
  const result = await tryPost(import.meta.env.VITE_API_BASEURL + '/api/tweets', accessToken.value)
  // if(result.response == 200){
  //   handleFetching()
  // }
}

const toggleModal = () => {
  console.log("click");
  showModal.value = !showModal.value;
};

onMounted(() => {
  handleFetching()
})

// watch(data, () => {
//   handleFetching()
// })
</script>
