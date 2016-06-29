/*jshint node:true*/
'use strict';

module.exports = function(grunt) {

	require('time-grunt')(grunt);

	grunt.initConfig({
		karma: {
			options: {
				singleRun: true,
				reporters: ['dots']
			},
			headless: {
				configFile: 'test/karma.conf.js',
				browsers: ['PhantomJS']
			},
			browsers: {
				configFile: 'test/karma.conf.js',
				browsers: ['Chrome', 'Firefox', 'Safari', 'Opera']
			}
		}
	});

	grunt.loadNpmTasks('grunt-karma');
	grunt.loadNpmTasks('time-grunt');

	grunt.registerTask('test', ['karma:headless']);
};
