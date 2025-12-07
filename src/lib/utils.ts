import bip39 from '../data/bip39';
import {randomInt} from 'crypto';

/**
 * Generates a space-separated string of pseudo-random words selected from the BIP39 English wordlist.
 *
 * @param length - Number of words to generate (must be >= 1). Defaults to 3.
 * @returns A string containing the requested number of words separated by single spaces.
 *
 * @throws {Error} If `length` is less than 1.
 * @throws {Error} If the BIP39 English wordlist cannot be resolved or is empty.
 *
 * @remarks
 * - Imports the BIP39 English wordlist as an array from `../data/bip39`.
 * - Uses Node.js `crypto.randomInt()` which is cryptographically secure.
 * - The function does not enforce uniqueness; words may repeat.
 *
 * @example
 * // Default: three words
 * const three = generateRandomWords(); // e.g., "echo rain gesture"
 *
 * @example
 * // Custom length
 * const five = generateRandomWords(5); // e.g., "galaxy vivid leaf humble rookie"
 *
 * @example
 * // Handling errors
 * try {
 *   const one = generateRandomWords(1);
 * } catch (err) {
 *   console.error(err);
 * }
 */
export const generateRandomWords = (length: number = 3): string => {
    if (length < 1) throw new Error('length must be at least 1');

    const list = bip39 ?? []
    if (!Array.isArray(list) || list.length === 0) {
        throw new Error('BIP39 English wordlist unavailable');
    }

    const words: string[] = [];
    for (let i = 0; i < length; i++) {
        words.push(list[randomInt(list.length)]!);
    }

    return words.join(' ');
};