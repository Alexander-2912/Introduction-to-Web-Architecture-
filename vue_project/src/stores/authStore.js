import {defineStore} from 'pinia'
import {ref, computed, watch} from 'vue'

export const useAuthStore = defineStore('auth', () => {
    const accessToken = ref(null)
    const refreshToken = ref(null)

    const persistAccessToken = localStorage.getItem("accessToken")
    const persistRefreshToken = localStorage.getItem("refreshToken")

    if((persistAccessToken != persistRefreshToken) != null){
        accessToken.value = persistAccessToken
        refreshToken.value = persistRefreshToken
    }

watch(accessToken.value, (newAccessToken) => {
    accessToken = newAccessToken
})


    const isAuthenticated = computed(() => {
        return accessToken.value != null
    })

    //actions
    const setToken = (access_token, refresh_token) => {
        localStorage.setItem('accessToken', access_token)
        localStorage.setItem('refreshToken', refresh_token)
        accessToken.value = access_token
        refreshToken.value = refresh_token
    }
    const removeToken = () => {
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
        accessToken.value = null
        refreshToken.value = null
    }

    return{
        accessToken, refreshToken, isAuthenticated, setToken, removeToken
    }
},
)