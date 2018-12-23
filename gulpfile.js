var gulp = require('gulp');
var ts = require('gulp-typescript');
var tsProject = ts.createProject("tsconfig.json");

gulp.task('watch', () => {
  gulp.watch(['./src/**/*.ts'], gulp.series('typescript'));
});

gulp.task('typescript', () => {
  return gulp.src('src/**/*.ts').pipe(tsProject()).js.pipe(gulp.dest('./'));
});

gulp.task('default', gulp.series('typescript', 'watch'));