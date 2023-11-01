<template>
    <nav class="flex justify-around items-center bg-green-500 p-3 text-white">
        <h1>Simple Twitter</h1>
        <ul class="flex gap-5">
            <RouterLink to="/" exact active-class="border-2 border-white p-1">Home</RouterLink>
            <RouterLink to="/leaderboard" exact active-class="border-2 border-white p-1">Leaderboard</RouterLink>
            <RouterLink to="/login" exact active-class="border-2 border-white p-1">Login</RouterLink>
            <RouterLink to="/register" exact active-class="border-2 border-white p-1">Register</RouterLink>
            <a to="/logout" class="border-2 border-white p-1" @click="handleLogout">Logout</a>
            <!-- <a :href="urlAdmin" class="border-2 border-white p-1">Admin</a> -->
        </ul>
    </nav>
</template>

<script setup>
import {RouterLink} from 'vue-router'
import Swal from 'sweetalert2'
import { useRouter } from 'vue-router';
import { useAuthStore } from '../../stores/authStore';


const urlAdmin = import.meta.env.VITE_API_BASEURL + "/admin"
const {removeToken} = useAuthStore()
const router = useRouter()
const handleLogout = () => {
    Swal.fire({
  title: 'Are you sure?',
  text: "You won't be able to revert this!",
  icon: 'warning',
  showCancelButton: true,
  confirmButtonColor: '#3085d6',
  cancelButtonColor: '#d33',
  confirmButtonText: 'Yes, delete it!'
}).then((result) => {
  if (result.isConfirmed) {
    removeToken()
    router.push('/login')
  }
})
}



</script>