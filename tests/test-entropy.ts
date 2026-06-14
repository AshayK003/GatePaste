import { isHighEntropy, shannonEntropy } from '../utils/entropy';

console.log('Entropy of hex key:', shannonEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4').toFixed(2));
console.log('  isHighEntropy():', isHighEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'));
console.log('  isHighEntropy(3.5):', isHighEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 3.5));
console.log();
console.log('Entropy of natural lang:', shannonEntropy('The quick brown fox jumps over the lazy dog').toFixed(2));
console.log('  isHighEntropy():', isHighEntropy('The quick brown fox jumps over the lazy dog'));
console.log('  isHighEntropy(4.0):', isHighEntropy('The quick brown fox jumps over the lazy dog', 4.0));
