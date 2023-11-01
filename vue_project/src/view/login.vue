<template>
  <div class="p-20">
    <formC>
      <!-- <span v-if="errorMsg" class="bg-red-500 p-4"> {{ errorMsg }}</span> -->
      <inputC
        id-input="username"
        input-type="text"
        label-name="Username"
        v-model="userData.username"
      />
      <p v-if="validationError.username" class="text-red-500">
        {{ validationError.username }}
      </p>
      <inputC
        id-input="password"
        input-type="password"
        label-name="Password"
        v-model="userData.password"
      />
      <p v-if="validationError.password" class="text-red-500">
        {{ validationError.password }}
      </p>

      <buttonC name="Submit" btn-type="submit" @handle-click="handleLogin" />
      <RouterLink to="/register" class="text-blue-500 hover:underline"
        >Register</RouterLink
      >
    </formC>
  </div>
</template>

<script setup>
import formC from "../components/UI/form.vue";
import inputC from "../components/UI/input.vue";
import buttonC from "../components/UI/button.vue";
import { reactive, ref } from "vue";
import { useRouter, RouterLink } from "vue-router";
import { useAuth } from "../composable/useAuth";
import { useAuthStore } from "../stores/authStore";
import Swal from "sweetalert2";

const { setToken } = useAuthStore();

const success = ref(false);
const accessToken = ref();
const refreshToken = ref();

const { tryAuth, errorMsg } = useAuth();

const router = useRouter();

const userData = reactive({
  username: "",
  password: "",
});

const validationError = reactive({
  username: "",
  password: "",
});

const handleLogin = async () => {
  Object.keys(validationError).forEach((key) => {
    validationError[key] = "";
  });

  let isValid = ref(true);
  if (!userData.username) {
    validationError.username = "Username is required";
    isValid.value = false;
  }
  if (!userData.password) {
    validationError.password = "Password is required";
    isValid.value = false;
  }

  if (isValid) {
    const result = await tryAuth(
      import.meta.env.VITE_API_BASEURL + "/api/auth/login",
      userData
    );
    success.value = result.data.success;
    accessToken.value = result.data.access_token;
    refreshToken.value = result.data.refresh_token;
    setToken(accessToken.value, refreshToken.value);
    if (success.value == true) {
      Swal.fire("Welcome to Simple Twitter!");
      router.push("/");
    }
  }
};
</script>
