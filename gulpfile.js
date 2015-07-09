'use strict';

var gulp = require('gulp');
var rename = require('gulp-rename');
var ngAnnotate = require('gulp-ng-annotate');
var uglify = require('gulp-uglify');
var header = require('gulp-header');
var pkg = require('./package.json');

var banner = ['/**',
    ' * <%= pkg.name %> - <%= pkg.description %>',
    ' * @version v<%= pkg.version %>',
    ' * (c) 2015 <%= pkg.author.name %>',
    ' * @link <%= pkg.homepage %>',
    ' * @license <%= pkg.license %>',
    ' */',
    ''
].join('\n');

gulp.task('minify', function() {
  return gulp.src('ngbearerauth.js')
    .pipe(ngAnnotate())
    .pipe(uglify())
    .pipe(header(banner, { pkg: pkg }))
    .pipe(rename({ suffix: '.min' }))
    .pipe(gulp.dest('.'));
});

gulp.task('watch', function() {
  gulp.watch('ngbearerauth.js', ['minify']);
});

gulp.task('default', ['minify']);