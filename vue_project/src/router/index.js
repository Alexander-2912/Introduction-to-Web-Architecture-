import { createRouter, createWebHistory} from 'vue-router'

import homeC from "../view/home.vue"
import leaderboardC from "../view/leaderboard.vue"
import loginC from "../view/login.vue"
import registerC from "../view/register.vue"
import { useAuthStore } from '../stores/authStore.js'

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: "/",
            name: "home",
            component: homeC,
            meta: {
                requiresAuth : true
            }
        },
        {
            path: "/leaderboard",
            name: "leaderboard",
            component: leaderboardC,
            meta: {
                requiresAuth : true
            }
        },
        {
            path: "/login",
            name: "login",
            component: loginC
        },
        {
            path: "/register",
            name: "register",
            component: registerC
        },
    ]
})

router.beforeEach((to, from, next) => {
    const {isAuthenticated} = useAuthStore()

    if(to.meta.requiresAuth){
        if(isAuthenticated){
            next()
        }else{
            next('/login')
        }
    }else{
        next()
    }
})
export default router