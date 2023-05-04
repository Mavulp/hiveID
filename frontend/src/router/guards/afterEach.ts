import type { RouteLocationNormalized } from 'vue-router'

// This guard is executed after every route is resolved
export default async function (to: RouteLocationNormalized, from: RouteLocationNormalized) {

  // Set the document title to the meta field we provide when setting up the router
  document.title = `${to.meta.title} // Hivecom Emotes`

  // Automatically scroll up 
  window.scrollTo({ top: 0, behavior: 'smooth' })
}
