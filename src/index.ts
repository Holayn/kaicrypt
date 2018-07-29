import * as crypto from 'crypto';
import { debug } from 'util';
import {Promise} from 'es6-promise';

const ivLength: number = 16;
const algorithm: string = 'aes256';
const outputEncoding: any = 'base64';
const inputEncoding: any = 'utf8';
const delimiter: any = ';';

export function encrypt(stringToEncrypt: any, key: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    const iv = crypto.randomBytes(ivLength, (err: any, buf: any) => {
      if (err) {
        reject(err);
      }
      // turn user key into 32 byte buffer
      const hashKey: Buffer = createHashKey(key);
      const cipher = crypto.createCipheriv(algorithm, hashKey, buf);
      let encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
      encrypted += cipher.final(outputEncoding);
      resolve(encrypted + delimiter + buf.toString(outputEncoding));
    });
  });
}

export function decrypt(stringToDecrypt: string, key: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    try {
      const stringSplit: string[] = stringToDecrypt.split(delimiter);
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
  const hashKey = crypto.randomBytes(32);
  return crypto.createHmac('sha256', secret)
    .update(keyToHash)
    .digest();

}
