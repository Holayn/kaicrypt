import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';
import {Promise} from 'es6-promise';
import { resolve } from 'dns';
import { Observable, Observer } from 'rxjs';

const ivLength: number = 16;
const algorithm: string = 'aes256';
const outputEncoding: any = 'base64';
const inputEncoding: any = 'utf8';
const delimiter: any = ';';

export function encrypt(stringToEncrypt: any, secret: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    crypto.randomBytes(ivLength, (err: any, iv: any) => {
      if (err) {
        reject(err);
      }
      // aes256 requires 32 byte buffer as a key
      const hashKey: Buffer = createHashKey(secret);
      const cipher = crypto.createCipheriv(algorithm, hashKey, iv);
      let encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
      encrypted += cipher.final(outputEncoding);
      resolve(encrypted + delimiter + iv.toString(outputEncoding));
    });
  });
}

export function decrypt(stringToDecrypt: string, secret: string): Promise<string> {
  return new Promise<string>((resolve: any, reject: any) => {
    try {
      const stringSplit: string[] = stringToDecrypt.split(delimiter);
      // aes256 requires 32 byte buffer as a key
      const hashKey: Buffer = createHashKey(secret);
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

/**
 * https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
 * @param stringToEncrypt 
 * @param secret 
 */
export function encryptPBKDF2(stringToEncrypt: any, secret: any): Observable<string> {
  const keySize = 256;
  const ivSize = 128;
  const iterations = 10000;
  return Observable.create((observer: Observer<string>) => {
    const salt = CryptoJS.lib.WordArray.random(ivSize/8);
    const key = CryptoJS.PBKDF2(secret, salt, {
      keySize: keySize/32,
      iterations: iterations
    });
    const iv = CryptoJS.lib.WordArray.random(128/8);

    const encrypted = CryptoJS.AES.encrypt(stringToEncrypt, key, { 
      iv: iv, 
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC
    });

    // salt, iv will be hex 32 in length
    // append them to the ciphertext for use  in decryption
    var transitmessage = salt.toString()+ iv.toString() + encrypted.toString();
    observer.next(transitmessage);
  });
}

/**
 * https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
 * @param secret 
 * @param stringToDecrypt 
 */
export function decryptPBKDF2(secret: string, stringToDecrypt: string): Observable<string> {
  const keySize = 256;
  const iterations = 10000;
  return Observable.create((observer: Observer<string>) => {
    const salt = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(0, 32));
    const iv = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(32, 32))
    const encrypted = stringToDecrypt.substring(64);
    
    const key = CryptoJS.PBKDF2(secret, salt, {
      keySize: keySize/32,
      iterations: iterations
    });

    const decrypted = CryptoJS.AES.decrypt(encrypted, key, { 
      iv: iv, 
      padding: CryptoJS.pad.Pkcs7,
      mode: CryptoJS.mode.CBC
    });

    observer.next(decrypted.toString(CryptoJS.enc.Utf8));
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