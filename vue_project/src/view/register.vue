<template>
  <div class="p-20">
    <formC>
      <p v-if="success" class="bg-green-500 p-3 text-white">{{ message }}</p>
      <inputC
        id-input="username"
        input-type="text"
        label-name="Username"
        v-model="userData.username"
      />
      <inputC
        id-input="email"
        input-type="email"
        label-name="Email"
        v-model="userData.email"
      />
      <inputC
        id-input="password"
        input-type="password"
        label-name="Password"
        v-model="userData.password"
      />
      <inputC
        id-input="confirm_password"
        input-type="password"
        label-name="Confirm Password"
        v-model="confirmPassword"
      />
      <buttonC name="Submit" btn-type="submit" @handle-click="handleRegister" />
      <RouterLink to="/login" class="text-blue-500 hover:underline"
        >Kembali ke login</RouterLink>
    </formC>
  </div>
</template>

<script setup>
import formC from "../components/UI/form.vue";
import inputC from "../components/UI/input.vue";
import buttonC from "../components/UI/button.vue";
import { reactive, ref } from "vue";
import { useAuth } from "../composable/useAuth";
import { RouterLink } from "vue-router";

const userData = reactive({
  username: "",
  password: "",
  email: "",
});

const confirmPassword = ref("");

const success = ref(false);
const message = ref();

const { tryAuth } = useAuth();

const handleRegister = async () => {
  if (confirmPassword.value == userData.password) {
    const result = await tryAuth(
      import.meta.env.VITE_API_BASEURL + "/api/auth/register",
    userData
    );
    success.value = result.data.success;
    message.value = result.data.message;
  }
};
</script>
