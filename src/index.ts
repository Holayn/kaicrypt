import * as crypto from 'crypto';
import {Promise} from 'es6-promise';

const ivLength: number = 16;
const algorithm: string = 'aes256';
const outputEncoding: any = 'base64';
const inputEncoding: any = 'utf8';
const delimiter: any = ';';

export function encrypt(stringToEncrypt: any, key: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    crypto.randomBytes(ivLength, (err: any, iv: any) => {
      if (err) {
        reject(err);
      }
      // aes256 requires 32 byte buffer as a key
      const hashKey: Buffer = createHashKey(key);
      const cipher = crypto.createCipheriv(algorithm, hashKey, iv);
      let encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
      encrypted += cipher.final(outputEncoding);
      resolve(encrypted + delimiter + iv.toString(outputEncoding));
    });
  });
}

export function decrypt(stringToDecrypt: string, key: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    try {
      const stringSplit: string[] = stringToDecrypt.split(delimiter);
      // aes256 requires 32 byte buffer as a key
      const hashKey: Buffer = createHashKey(key);
      const iv: Buffer = new Buffer(stringSplit[1], outputEncoding);
      const decipher = crypto.createDecipheriv(algorithm, hashKey, iv);
      let decrypted = decipher.update(stringToDecrypt, outputEncoding, inputEncoding);
      decrypted += decipher.final(inputEncoding);
      resolve(decrypted);
    }
    catch(err){
      reject(err);
    }
  });
}

function createHashKey(keyToHash: string): Buffer {
  const secret = "kwdingdong";
  // sha256 turns a string to a 32 byte buffer
  return crypto.createHmac('sha256', secret)
    .update(keyToHash)
    .digest();
}

export function hashWithSHA256(keyToHash: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(keyToHash);
  return hash.digest('hex');
}