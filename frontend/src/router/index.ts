import { createRouter, createWebHistory } from 'vue-router'

import afterEach from './guards/afterEach'

// import RouterMain from './routes/router-main'
// import RouterQuote from './routes/router-quote'
import RouteHome from './views/RouteHome.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      // Special route used as a catch-all.
      path: '/:pathMatch(.*)*',
      // In case user wants to access a path which is not defined,
      // they will be redirected to the following route
      redirect: {
        name: 'RouteHome',
      },
    },
    {
      // The path to the the page
      path: '/home',
      // Name is used for matching routes. Allowing you to change url
      // to the page without having to update all the
      name: 'RouteHome',
      component: RouteHome,
      // The meta object contains whatever properties you want
      // In our
      meta: {
        title: 'Home',
      },
    },
  ],
})

// Register router guards
router.afterEach(afterEach)

export default router
