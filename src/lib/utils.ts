import bip39 from 'bip39';

export const generateRandomWords = (length: number = 3): string => {
    const words = bip39.generateMnemonic(length * 3).split(' ');
    return words.slice(0, length).join(' ');
};