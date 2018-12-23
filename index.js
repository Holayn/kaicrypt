"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var CryptoJS = require("crypto-js");
var bcrypt = require("bcryptjs");
var es6_promise_1 = require("es6-promise");
var rxjs_1 = require("rxjs");
var ivLength = 16;
var algorithm = 'aes256';
var outputEncoding = 'base64';
var inputEncoding = 'utf8';
var delimiter = ';';
function encrypt(stringToEncrypt, secret) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        crypto.randomBytes(ivLength, function (err, iv) {
            if (err) {
                reject(err);
            }
            // aes256 requires 32 byte buffer as a key
            var hashKey = createHashKey(secret);
            var cipher = crypto.createCipheriv(algorithm, hashKey, iv);
            var encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
            encrypted += cipher.final(outputEncoding);
            resolve(encrypted + delimiter + iv.toString(outputEncoding));
        });
    });
}
exports.encrypt = encrypt;
function decrypt(stringToDecrypt, secret) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        try {
            var stringSplit = stringToDecrypt.split(delimiter);
            // aes256 requires 32 byte buffer as a key
            var hashKey = createHashKey(secret);
            var iv = new Buffer(stringSplit[1], outputEncoding);
            var decipher = crypto.createDecipheriv(algorithm, hashKey, iv);
            var decrypted = decipher.update(stringToDecrypt, outputEncoding, inputEncoding);
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
    var keySize = 256;
    var ivSize = 128;
    var iterations = 10000;
    return rxjs_1.Observable.create(function (observer) {
        var salt = CryptoJS.lib.WordArray.random(ivSize / 8);
        var key = CryptoJS.PBKDF2(secret, salt, {
            keySize: keySize / 32,
            iterations: iterations
        });
        var iv = CryptoJS.lib.WordArray.random(128 / 8);
        var encrypted = CryptoJS.AES.encrypt(stringToEncrypt, key, {
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
    var keySize = 256;
    var iterations = 10000;
    return rxjs_1.Observable.create(function (observer) {
        var salt = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(0, 32));
        var iv = CryptoJS.enc.Hex.parse(stringToDecrypt.substr(32, 32));
        var encrypted = stringToDecrypt.substring(64);
        var key = CryptoJS.PBKDF2(secret, salt, {
            keySize: keySize / 32,
            iterations: iterations
        });
        var decrypted = CryptoJS.AES.decrypt(encrypted, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });
        observer.next(decrypted.toString(CryptoJS.enc.Utf8));
    });
}
exports.decryptPBKDF2 = decryptPBKDF2;
function encryptBcryptAES(stringToEncrypt, secret) {
    return rxjs_1.Observable.create(function (observer) {
        bcrypt.genSalt(12, function (err, salt) {
            bcrypt.hash(secret, salt, function (err, hash) {
                var iv = CryptoJS.lib.WordArray.random(128 / 8);
                var encrypted = CryptoJS.AES.encrypt(stringToEncrypt, hash, {
                    iv: iv,
                    padding: CryptoJS.pad.Pkcs7,
                    mode: CryptoJS.mode.CBC
                });
                // salt, iv will be hex 32 in length
                // append them to the ciphertext for use  in decryption
                var transitmessage = salt.toString() + iv.toString() + encrypted.toString();
                observer.next(transitmessage);
            });
        });
    });
}
exports.encryptBcryptAES = encryptBcryptAES;
/**
 * https://embed.plnkr.co/0VPU1zmmWC5wmTKPKnhg/
 * @param stringToDecrypt
 * @param secret
 */
function decryptBcryptAES(stringToDecrypt, secret) {
    return rxjs_1.Observable.create(function (observer) {
        var salt = stringToDecrypt.substr(0, 29);
        var iv = stringToDecrypt.substr(29, 32);
        var encrypted = stringToDecrypt.substring(61);
        bcrypt.hash(secret, salt, function (err, hash) {
            var decrypted = CryptoJS.AES.decrypt(encrypted, hash, {
                iv: iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC
            });
            observer.next(decrypted.toString(CryptoJS.enc.Utf8));
        });
    });
}
exports.decryptBcryptAES = decryptBcryptAES;
function createHashKey(keyToHash) {
    var secret = "kwdingdong";
    // sha256 turns a string to a 32 byte buffer
    return crypto.createHmac('sha256', secret)
        .update(keyToHash)
        .digest();
}
function hashWithSHA256(keyToHash) {
    var hash = crypto.createHash('sha256');
    hash.update(keyToHash);
    return hash.digest('hex');
}
exports.hashWithSHA256 = hashWithSHA256;
function hashWithBcrypt(keyToHash) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        bcrypt.genSalt(12, function (err, salt) {
            bcrypt.hash(keyToHash, salt, function (err, hash) {
                resolve(hash);
            });
        });
    });
}
exports.hashWithBcrypt = hashWithBcrypt;
