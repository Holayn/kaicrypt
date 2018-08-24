var test = require('./index');

const res = test.encrypt('123', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3');
res.then((str) => {;
  test.decrypt(str, 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3').then((asdfasdf) => {
    console.log(asdfasdf);
  })
  test.decrypt("yinMG9s6Xeszx7boI90Ijg==;KYICQOuQZRdQzEDJ5TzM6g==", 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3').then((asdf) => {
    console.log(asdf);
  });
});