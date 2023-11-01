import axios from 'axios'
import {ref} from 'vue'
import axiosinstance from '../lib/axios/axiosInstance'

export function useAxios(){
    const tryFetch = async (url, page, per_page) => {
        try{
            const response = await axiosinstance.get(url, {
                params: {
                    page: page,
                    per_page: per_page
                }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    const tryPost = async (url) => {
        try{
            const response = await axiosinstance.post(url, formData, {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
              }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    const tryUpload = async (url) => {
        try{
            const response = await axiosinstance.post(url, formData, {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'multipart/form-data'
              }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    return {
        tryFetch,
    }
}