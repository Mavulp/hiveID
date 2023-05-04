/**
 * This file contains the global (develper defined) variables to use in the front-end.
 */

// The root api url, eg: https://api.service.com
export const API_URL = ''

// Checks wether the site is viewed in a local server or not
export const __DEV__ = Boolean(
  window.location.hostname === 'localhost'
  // [::1] is the IPv6 localhost address.
  || window.location.hostname === '[::1]'
  // 127.0.0.1/8 is considered localhost for IPv4.
  || window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/),
)
