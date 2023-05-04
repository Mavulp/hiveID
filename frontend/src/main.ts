import { createApp } from 'vue'
import './style/index.scss'
import { Icon } from '@iconify/vue'
import App from './App.vue'
import router from './router'

/**
 * This is the main application entry point.
 * You can import and register global component
 * or install plugins into the vue instance.
 */

const app = createApp(App)

// Register plugins in the app
app.use(router)

// Register global components, available without having to specify an import
app.component('Icon', Icon)

// Finally, append the entire app the the <div id="app" />
app.mount('#app')
