"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const CryptoJS = require("crypto-js");
const es6_promise_1 = require("es6-promise");
const rxjs_1 = require("rxjs");
const ivLength = 16;
const algorithm = 'aes256';
const outputEncoding = 'base64';
const inputEncoding = 'utf8';
const delimiter = ';';
function encrypt(stringToEncrypt, secret) {
    return new es6_promise_1.Promise((resolve, reject) => {
        crypto.randomBytes(ivLength, (err, iv) => {
            if (err) {
                reject(err);
            }
            // aes256 requires 32 byte buffer as a key
            const hashKey = createHashKey(secret);
            const cipher = crypto.createCipheriv(algorithm, hashKey, iv);
            let encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
            encrypted += cipher.final(outputEncoding);
            resolve(encrypted + delimiter + iv.toString(outputEncoding));
        });
    });
}
exports.encrypt = encrypt;
function decrypt(stringToDecrypt, secret) {
    return new es6_promise_1.Promise((resolve, reject) => {
        try {
            const stringSplit = stringToDecrypt.split(delimiter);
            // aes256 requires 32 byte buffer as a key
            const hashKey = createHashKey(secret);
            const iv = new Buffer(stringSplit[1], outputEncoding);
            const decipher = crypto.createDecipheriv(algorithm, hashKey, iv);
            let decrypted = decipher.update(stringToDecrypt, outputEncoding, inputEncoding);
            decrypted += decipher.final(inputEncoding);
            resolve(decrypted);
        }
        catch (err) {
            reject(err);
        }
    });
}
exports.decrypt = decrypt;
/**
 * https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
 * @param stringToEncrypt
 * @param secret
 */
function encryptPBKDF2(stringToEncrypt, secret) {
    const keySize = 256;
    const ivSize = 128;
    const iterations = 10000;
    return rxjs_1.Observable.create((observer) => {
        const salt = CryptoJS.lib.WordArray.random(ivSize / 8);
        const key = CryptoJS.PBKDF2(secret, salt, {
            keySize: keySize / 32,
            iterations: iterations
        });
        const iv = CryptoJS.lib.WordArray.random(128 / 8);
        const encrypted = CryptoJS.AES.encrypt(stringToEncrypt, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });
        // salt, iv will be hex 32 in length
        // append them to the ciphertext for use  in decryption
        var transitmessage = salt.toString() + iv.toString() + encrypted.toString();
        observer.next(transitmessage);
    });
}
exports.encryptPBKDF2 = encryptPBKDF2;
/**
 * https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
 * @param secret
 * @param stringToDecrypt
 */
function decryptPBKDF2(secret, stringToDecrypt) {
    const keySize = 256;
    const iterations = 10000;
    return rxjs_1.Observable.create((observer) => {
        const salt = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(0, 32));
        const iv = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(32, 32));
        const encrypted = stringToDecrypt.substring(64);
        const key = CryptoJS.PBKDF2(secret, salt, {
            keySize: keySize / 32,
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
exports.decryptPBKDF2 = decryptPBKDF2;
function createHashKey(keyToHash) {
    const secret = "kwdingdong";
    // sha256 turns a string to a 32 byte buffer
    return crypto.createHmac('sha256', secret)
        .update(keyToHash)
        .digest();
}
function hashSHA256(keyToHash) {
    const hash = crypto.createHash('sha256');
    hash.update(keyToHash);
    return hash.digest('hex');
}
exports.hashSHA256 = hashSHA256;
function hashSHA512(keyToHash) {
    const hash = crypto.createHash('sha512');
    hash.update(keyToHash);
    return hash.digest('hex');
}
exports.hashSHA512 = hashSHA512;
