import axios from 'axios'
import { useAuthStore } from '../../stores/authStore';
import { storeToRefs } from 'pinia';

// const store 
const axiosinstance = axios.create({
    baseURL: import.meta.env.VITE_API_BASEURL,
    timeout: 100000,
  });
  axiosinstance.interceptors.request.use(
    (config) => {
        const accessToken = localStorage.getItem("accessToken")
        if(accessToken){
            config.headers.Authorization = `Bearer ${accessToken}`
        }
        return config
    },
    (error) => {
        return Promise.reject(error)
    }
  )

axiosinstance.interceptors.response.use(
    (response) => {
        return response
    },
    async (error) => {
        const originalRequest = error.config
        if(error.response.status == 401 && !originalRequest._retry){
            originalRequest._retry = true
            try{
                const refreshToken = localStorage.getItem('refreshToken')
                const response = await axios.post(import.meta.env.VITE_API_BASEURL + '/api/auth/refresh', null, {
                    headers: {
                        Authorization: `Bearer ${refreshToken}`
                    }
                })
                const newAccessToken = response.data.access_token
                localStorage.setItem('accessToken', newAccessToken)
                originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
                return axiosinstance(originalRequest)
            }catch(err){
                console.log(err)
            }
        }
    }
)

  export default axiosinstance