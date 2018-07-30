var test = require('./index');

const res = test.encrypt('wendy sux', 'asdf');
res.then((str) => {
  test.decrypt(str, 'asdf').then((asdfasdf) => {
    console.log(asdfasdf);
  })

  }
}).catch((err) => {
  console.log(err);
});




class Promise {
 then(cb) {



  cb(resolveParam)
 }
}
