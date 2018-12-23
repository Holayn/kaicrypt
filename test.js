var test = require('./index');

const res = test.encryptBcryptAES('$jaodsijfAJAjsiad2iaoijdjaodsijfAJAjsiad2iaoijd', '19280798327410298740982141');
res.subscribe((str) => {
  test.decryptBcryptAES(str.toString(), '19280798327410298740982141').subscribe((result) => {
    console.log(result);
  });
}, (err) => {
  console.log(err);
});


test.hashWithBcrypt('hi').then((res) => {
  console.log(res);
})


class Promise {
 then(cb) {



  cb(resolveParam)
 }
}
