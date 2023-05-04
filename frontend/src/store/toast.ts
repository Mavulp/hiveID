import { defineStore } from 'pinia'

/**
 * This is a simple store to push a toast notification from anywhere in the application.
 * Allowing you to add a button to it and execute a function on click.
 *
 */

export interface Toast {
  type?: 'error' | 'info' | 'success' | 'text'
  message: string
  action?: {
    label: string
    fn: (self: SerializedToast) => void
  }
}

export interface SerializedToast extends Toast {
  _id: number
  _expire: number
  _created: number
  _persist: boolean // If set to true, won't auto clear
}

interface State {
  items: Map<number, SerializedToast>
  id: number
}

export const useToast = defineStore('toast', {
  state: () => ({
    items: new Map(),
    id: 0,
  } as State),
  actions: {
    push({ type, message, action }: Toast, persist = false) {
      const id = this.id
      // Toast message LEN * 50, minimum is 2s, max is 7s
      const expiresIn = Math.min(Math.max(message.length * 50, 2500), 7000)

      this.items.set(id,
        {
          type: type ?? 'text',
          message,
          action,

          _id: id,
          _created: Date.now(),
          _expire: expiresIn,
          _persist: persist,
        },
      )

      // Remove when toast expires
      if (!persist)
        setTimeout(() => this.del(id), expiresIn)

      this.id++
    },
    del(id: number) {
      this.items.delete(id)
    },
    clear() {
      this.items.clear()
    },
  },
})
