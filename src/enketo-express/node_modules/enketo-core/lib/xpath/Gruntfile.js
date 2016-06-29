/*jshint node:true*/
"use strict";

module.exports = function(grunt) {

	require( 'time-grunt' )( grunt );

	grunt.initConfig({
		php: {
			server: {
				options: {
					port: 8080
				}
			}
		},
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

	grunt.loadNpmTasks('grunt-php');
	grunt.loadNpmTasks('grunt-karma');
	grunt.loadNpmTasks('time-grunt');

	grunt.registerTask('server', ['php:server:keepalive']);
	grunt.registerTask('default', ['php:server:keepalive']);

	grunt.registerTask('test', ['karma:headless']);
};
