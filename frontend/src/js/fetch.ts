import { isArray, merge } from 'lodash-es'
import { useLoading } from '../store/loading'
import { API_URL } from './config'

/**
 * This is our small wrapper library about the browser's native fetch().
 * The main functionality is to simplify making requests into a one liner of code
 *
 * ```
 * await get<ReturnType>('/api/user', { ...options })
 * ```
 */

// TODO: Implement option to abort a fetch request by implementing the AbortController() class
// Controller used to abort requests
// export const controller = new AbortController()
// export const signal = controller.signal

export function get<T = any>(url: string, options?: object) {
  return _handleFetch<T>(
    url,
    merge(
      {
        method: 'GET',
      },
      options,
    ),
  )
}

export function post<T = any>(url: string, body: object | string, options?: object) {
  return _handleFetch<T>(
    url,
    merge(
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
      options,
    ),
  )
}

export function put<T = any>(url: string, body: object | string, options?: object) {
  return _handleFetch<T>(
    url,
    merge(
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
      options,
    ),
  )
}

export function del(url: string, options?: object) {
  return _handleFetch(
    url,
    merge(
      {
        method: 'DELETE',
      },
      options,
    ),
  )
}

/**
 * Special function to handle file uploads
 */

export function upload<T = any>(url: string, body: object | string, options?: object) {
  return _handleFetch<T>(url, {
    method: 'POST',
    body,
    ...options,
  })
}

// Private handler functions

async function _handleFetch<T>(url: string, options: object) {
  const token = localStorage.getItem('quotes_bearer_token')

  merge(options, {
    mode: 'cors',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  })

  if (url.includes('http'))
    return fetch(url, options).then<T>(_handleResponse)

  return fetch(API_URL + url, options).then<T>(_handleResponse)
}

async function _handleResponse(response: Response) {
  if (response.status !== 200) {
    return response.text().then((text: string) => {
      let message = null

      try {
        const parsed = JSON.parse(text)
        message = parsed.message
      }
      catch (e) {
        message = text
      }

      return Promise.reject(new Error(
        message || `An unexpected error occured: ${response.statusText}`,
      ))
    })
  }

  return response.text().then((text: string) => {
    const data = text && JSON.parse(text)

    if (!response.ok)
      return Promise.reject(data)

    return data
  })
}

// Wrapper for multiple requests
export async function $fetch<P>(name: string, promises: Promise<P>): Promise<P> {
  const loading = useLoading()
  loading.add(name)

  if (isArray(promises)) {
    return Promise.all(promises)
      .finally(() => {
        loading.del(name)
      }) as Promise<P>
  }

  return promises.finally(() => {
    loading.del(name)
  })
}
