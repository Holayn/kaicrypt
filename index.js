"use strict";
exports.__esModule = true;
var crypto = require("crypto");
var es6_promise_1 = require("es6-promise");
var ivLength = 16;
var algorithm = 'aes256';
var outputEncoding = 'base64';
var inputEncoding = 'utf8';
var delimiter = ';';
function encrypt(stringToEncrypt, key) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        crypto.randomBytes(ivLength, function (err, iv) {
            if (err) {
                reject(err);
            }
            // aes256 requires 32 byte buffer as a key
            var hashKey = createHashKey(key);
            var cipher = crypto.createCipheriv(algorithm, hashKey, iv);
            var encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
            encrypted += cipher.final(outputEncoding);
            resolve(encrypted + delimiter + iv.toString(outputEncoding));
        });
    });
}
exports.encrypt = encrypt;
function decrypt(stringToDecrypt, key) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        try {
            var stringSplit = stringToDecrypt.split(delimiter);
            // aes256 requires 32 byte buffer as a key
            var hashKey = createHashKey(key);
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
