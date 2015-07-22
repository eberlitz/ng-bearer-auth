'use strict';

var gulp = require('gulp');
var rename = require('gulp-rename');
var ngAnnotate = require('gulp-ng-annotate');
var uglify = require('gulp-uglify');
var header = require('gulp-header');
var pkg = require('./package.json');
var concat = require('gulp-concat');

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
    return gulp.src([
            'src/authservice.js',
            'src/ng-bearer-auth.js'
        ])
        .pipe(concat('ng-bearer-auth.js'))
        .pipe(header(banner, {
            pkg: pkg
        }))
        .pipe(gulp.dest('dist'))
        .pipe(ngAnnotate())
        .pipe(uglify())
        .pipe(header(banner, {
            pkg: pkg
        }))
        .pipe(rename({
            suffix: '.min'
        }))
        .pipe(gulp.dest('dist'));
});

gulp.task('watch', function() {
    gulp.watch([
        'src/authservice.js',
        'src/ng-bearer-auth.js'
    ], ['minify']);
});

gulp.task('default', ['minify']);