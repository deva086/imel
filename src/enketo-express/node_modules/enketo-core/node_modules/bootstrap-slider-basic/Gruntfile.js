/*global module:false*/
module.exports = function( grunt ) {

    // Project configuration.
    grunt.initConfig( {
        pkg: grunt.file.readJSON( 'package.json' ),
        jshint: {
            options: {
                jshintrc: ".jshintrc"
            },
            all: [ "*.js", "js/**/*.js" ]
        },
        jasmine: {
            src: '<%= pkg.main %>',
            options: {
                specs: '<%= pkg.gruntConfig.spec %>',
                vendor: [ '<%= pkg.gruntConfig.js.jquery %>' ],
                template: '<%= pkg.gruntConfig.tpl.SpecRunner %>'
            }
        }
    } );

    grunt.loadNpmTasks( 'grunt-contrib-jshint' );
    grunt.loadNpmTasks( 'grunt-contrib-jasmine' );

    grunt.registerTask( 'test', [ 'jshint', 'jasmine' ] );
};
