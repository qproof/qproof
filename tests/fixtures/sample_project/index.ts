import crypto from 'crypto';
import { createCipheriv, createHash } from 'crypto';

const hash = createHash('sha256');
const cipher = createCipheriv('aes-128-cbc', key, iv);

export function generateRSAKey() {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
