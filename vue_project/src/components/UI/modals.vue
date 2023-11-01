<template>
  <Dialog :open="isOpen" @close="toggleModal">
    <div class="fixed inset-0 bg-black/30" aria-hidden="true" />
    <div class="fixed inset-0 flex w-100 items-center justify-center p-4">
    <DialogPanel class="bg-white p-5 rounded-md">
      <DialogTitle class="text-2xl my-6">Form Upload</DialogTitle>
      <DialogDescription>
        <formC class="flex gap-5 flex-col">
            <div class="flex flex-col">
                <label for="uploadFile">Upload File</label>
                <input type="file" id="uploadFile" class="input:border-none">
            </div>
            <div class="flex flex-col">
                <textAreaC label="Tweet"></textAreaC>
            </div>
        </formC>
      </DialogDescription>
      <div class="flex gap-5 mt-4">
          <buttonC @handle-click="$emit('closeModal')" name="Close"/>
          <buttonC @handle-click="$emit('uploadButton')" name="Upload"/>
      </div>

    </DialogPanel>
    </div>
  </Dialog>
</template>

<script setup>
import { ref } from "vue";
import {
  Dialog,
  DialogPanel,
  DialogTitle,
  DialogDescription,
} from "@headlessui/vue";

import buttonC from "./button.vue";
import formC from "./form.vue";
import textAreaC from "./customTextArea.vue";

defineProps(['isOpen']);

defineEmits(['closeModal'])

</script>
