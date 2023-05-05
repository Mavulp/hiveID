import { createRouter, createWebHistory } from 'vue-router'

import afterEach from './guards/afterEach'

// import RouterMain from './routes/router-main'
// import RouterQuote from './routes/router-quote'
import RouteHome from './views/RouteHome.vue'
import RouteInvitesVue from './views/RouteInvites.vue'
import RouteLogVue from './views/RouteLog.vue'
import RoutePermissionsVue from './views/RoutePermissions.vue'
import RouteServicesVue from './views/RouteServices.vue'
import RouteAccountVue from './views/RouteAccount.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/:pathMatch(.*)*',
      redirect: {
        name: 'RouteHome',
      },
    },
    {
      path: '/home',
      name: 'RouteHome',
      component: RouteHome,
      meta: { title: 'Home' },
    },
    {
      path: '/services',
      name: 'RouteServices',
      component: RouteServicesVue,
      meta: { title: 'Services' },
    },
    {
      path: '/permissions',
      name: 'RoutePermissions',
      component: RoutePermissionsVue,
      meta: { title: 'User Permissions' },
    },
    {
      path: '/invites',
      name: 'RouteInvites',
      component: RouteInvitesVue,
      meta: { title: 'Invites' },
    },
    {
      path: '/audit-log',
      name: 'RouteLog',
      component: RouteLogVue,
      meta: { title: 'Audit Log' },
    },
    {
      path: '/account',
      name: 'RouteAccount',
      component: RouteAccountVue,
      meta: { title: 'Account' },
    },
  ],
})

// Register router guards
router.afterEach(afterEach)

export default router
