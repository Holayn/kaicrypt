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
        var iv = crypto.randomBytes(ivLength, function (err, buf) {
            if (err) {
                reject(err);
            }
            // turn user key into 32 byte buffer
            var hashKey = createHashKey(key);
            var cipher = crypto.createCipheriv(algorithm, hashKey, buf);
            var encrypted = cipher.update(stringToEncrypt, inputEncoding, outputEncoding);
            encrypted += cipher.final(outputEncoding);
            resolve(encrypted + delimiter + buf.toString(outputEncoding));
        });
    });
}
exports.encrypt = encrypt;
function decrypt(stringToDecrypt, key) {
    return new es6_promise_1.Promise(function (resolve, reject) {
        try {
            var stringSplit = stringToDecrypt.split(delimiter);
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
    var hashKey = crypto.randomBytes(32);
    return crypto.createHmac('sha256', secret)
        .update(keyToHash)
        .digest();
}
