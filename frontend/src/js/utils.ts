import { isArray } from 'lodash-es'

/**
 * The scripts folder just contains any js / ts related stuff
 * Feel free to create sub folders and group relevant functionality in files etc. We're not strict, but appreciate clean code and structure :)
 */

// Return a random number in the provided range
export function getRanMinMax(min: number, max: number) {
  return Math.floor(Math.random() * (max - min) + min)
}

// Searches through the input and checkes wether it contains match
// It searches the input by splitting it by whitespace and matching each
// word against the string
export function searchInStr(match: string | string[], input: string) {
  if (!match)
    return false

  const joint: string = isArray(match) ? match.join(' ') : match

  const split = input.trim().split(/\s+/)
  return split.every(s => joint.toLowerCase().includes(s.toLowerCase()))
}
