var gulp = require('gulp');
var ts = require('gulp-typescript');

gulp.task('default', function () {
    return gulp.src('src/*.ts')
        .pipe(ts({
            noImplicitAny: false,
            "module": "commonjs",
            "target": "es2015"
        }))
        .pipe(gulp.dest(''));
});
