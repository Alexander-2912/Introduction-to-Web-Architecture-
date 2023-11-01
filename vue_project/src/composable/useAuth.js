import axios from 'axios'
import {ref} from 'vue'

export function useAuth(){

    const errorMsg = ref(null)
    const tryAuth = async (url, formData) => {
        try{
            axios.defaults.withCredentials = true
            const response = await axios.post(url, formData)
            return response
        }catch(e){
            errorMsg.value = e.response.data.error
        }
    }

    return {
        tryAuth,
        errorMsg
    }
}