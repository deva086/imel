(function () {/**
 * @license almond 0.2.9 Copyright (c) 2011-2014, The Dojo Foundation All Rights Reserved.
 * Available via the MIT or new BSD license.
 * see: http://github.com/jrburke/almond for details
 */
//Going sloppy to avoid 'use strict' string cost, but strict practices should
//be followed.
/*jslint sloppy: true */
/*global setTimeout: false */

var requirejs, require, define;
(function (undef) {
    var main, req, makeMap, handlers,
        defined = {},
        waiting = {},
        config = {},
        defining = {},
        hasOwn = Object.prototype.hasOwnProperty,
        aps = [].slice,
        jsSuffixRegExp = /\.js$/;

    function hasProp(obj, prop) {
        return hasOwn.call(obj, prop);
    }

    /**
     * Given a relative module name, like ./something, normalize it to
     * a real name that can be mapped to a path.
     * @param {String} name the relative name
     * @param {String} baseName a real name that the name arg is relative
     * to.
     * @returns {String} normalized name
     */
    function normalize(name, baseName) {
        var nameParts, nameSegment, mapValue, foundMap, lastIndex,
            foundI, foundStarMap, starI, i, j, part,
            baseParts = baseName && baseName.split("/"),
            map = config.map,
            starMap = (map && map['*']) || {};

        //Adjust any relative paths.
        if (name && name.charAt(0) === ".") {
            //If have a base name, try to normalize against it,
            //otherwise, assume it is a top-level require that will
            //be relative to baseUrl in the end.
            if (baseName) {
                //Convert baseName to array, and lop off the last part,
                //so that . matches that "directory" and not name of the baseName's
                //module. For instance, baseName of "one/two/three", maps to
                //"one/two/three.js", but we want the directory, "one/two" for
                //this normalization.
                baseParts = baseParts.slice(0, baseParts.length - 1);
                name = name.split('/');
                lastIndex = name.length - 1;

                // Node .js allowance:
                if (config.nodeIdCompat && jsSuffixRegExp.test(name[lastIndex])) {
                    name[lastIndex] = name[lastIndex].replace(jsSuffixRegExp, '');
                }

                name = baseParts.concat(name);

                //start trimDots
                for (i = 0; i < name.length; i += 1) {
                    part = name[i];
                    if (part === ".") {
                        name.splice(i, 1);
                        i -= 1;
                    } else if (part === "..") {
                        if (i === 1 && (name[2] === '..' || name[0] === '..')) {
                            //End of the line. Keep at least one non-dot
                            //path segment at the front so it can be mapped
                            //correctly to disk. Otherwise, there is likely
                            //no path mapping for a path starting with '..'.
                            //This can still fail, but catches the most reasonable
                            //uses of ..
                            break;
                        } else if (i > 0) {
                            name.splice(i - 1, 2);
                            i -= 2;
                        }
                    }
                }
                //end trimDots

                name = name.join("/");
            } else if (name.indexOf('./') === 0) {
                // No baseName, so this is ID is resolved relative
                // to baseUrl, pull off the leading dot.
                name = name.substring(2);
            }
        }

        //Apply map config if available.
        if ((baseParts || starMap) && map) {
            nameParts = name.split('/');

            for (i = nameParts.length; i > 0; i -= 1) {
                nameSegment = nameParts.slice(0, i).join("/");

                if (baseParts) {
                    //Find the longest baseName segment match in the config.
                    //So, do joins on the biggest to smallest lengths of baseParts.
                    for (j = baseParts.length; j > 0; j -= 1) {
                        mapValue = map[baseParts.slice(0, j).join('/')];

                        //baseName segment has  config, find if it has one for
                        //this name.
                        if (mapValue) {
                            mapValue = mapValue[nameSegment];
                            if (mapValue) {
                                //Match, update name to the new value.
                                foundMap = mapValue;
                                foundI = i;
                                break;
                            }
                        }
                    }
                }

                if (foundMap) {
                    break;
                }

                //Check for a star map match, but just hold on to it,
                //if there is a shorter segment match later in a matching
                //config, then favor over this star map.
                if (!foundStarMap && starMap && starMap[nameSegment]) {
                    foundStarMap = starMap[nameSegment];
                    starI = i;
                }
            }

            if (!foundMap && foundStarMap) {
                foundMap = foundStarMap;
                foundI = starI;
            }

            if (foundMap) {
                nameParts.splice(0, foundI, foundMap);
                name = nameParts.join('/');
            }
        }

        return name;
    }

    function makeRequire(relName, forceSync) {
        return function () {
            //A version of a require function that passes a moduleName
            //value for items that may need to
            //look up paths relative to the moduleName
            return req.apply(undef, aps.call(arguments, 0).concat([relName, forceSync]));
        };
    }

    function makeNormalize(relName) {
        return function (name) {
            return normalize(name, relName);
        };
    }

    function makeLoad(depName) {
        return function (value) {
            defined[depName] = value;
        };
    }

    function callDep(name) {
        if (hasProp(waiting, name)) {
            var args = waiting[name];
            delete waiting[name];
            defining[name] = true;
            main.apply(undef, args);
        }

        if (!hasProp(defined, name) && !hasProp(defining, name)) {
            throw new Error('No ' + name);
        }
        return defined[name];
    }

    //Turns a plugin!resource to [plugin, resource]
    //with the plugin being undefined if the name
    //did not have a plugin prefix.
    function splitPrefix(name) {
        var prefix,
            index = name ? name.indexOf('!') : -1;
        if (index > -1) {
            prefix = name.substring(0, index);
            name = name.substring(index + 1, name.length);
        }
        return [prefix, name];
    }

    /**
     * Makes a name map, normalizing the name, and using a plugin
     * for normalization if necessary. Grabs a ref to plugin
     * too, as an optimization.
     */
    makeMap = function (name, relName) {
        var plugin,
            parts = splitPrefix(name),
            prefix = parts[0];

        name = parts[1];

        if (prefix) {
            prefix = normalize(prefix, relName);
            plugin = callDep(prefix);
        }

        //Normalize according
        if (prefix) {
            if (plugin && plugin.normalize) {
                name = plugin.normalize(name, makeNormalize(relName));
            } else {
                name = normalize(name, relName);
            }
        } else {
            name = normalize(name, relName);
            parts = splitPrefix(name);
            prefix = parts[0];
            name = parts[1];
            if (prefix) {
                plugin = callDep(prefix);
            }
        }

        //Using ridiculous property names for space reasons
        return {
            f: prefix ? prefix + '!' + name : name, //fullName
            n: name,
            pr: prefix,
            p: plugin
        };
    };

    function makeConfig(name) {
        return function () {
            return (config && config.config && config.config[name]) || {};
        };
    }

    handlers = {
        require: function (name) {
            return makeRequire(name);
        },
        exports: function (name) {
            var e = defined[name];
            if (typeof e !== 'undefined') {
                return e;
            } else {
                return (defined[name] = {});
            }
        },
        module: function (name) {
            return {
                id: name,
                uri: '',
                exports: defined[name],
                config: makeConfig(name)
            };
        }
    };

    main = function (name, deps, callback, relName) {
        var cjsModule, depName, ret, map, i,
            args = [],
            callbackType = typeof callback,
            usingExports;

        //Use name if no relName
        relName = relName || name;

        //Call the callback to define the module, if necessary.
        if (callbackType === 'undefined' || callbackType === 'function') {
            //Pull out the defined dependencies and pass the ordered
            //values to the callback.
            //Default to [require, exports, module] if no deps
            deps = !deps.length && callback.length ? ['require', 'exports', 'module'] : deps;
            for (i = 0; i < deps.length; i += 1) {
                map = makeMap(deps[i], relName);
                depName = map.f;

                //Fast path CommonJS standard dependencies.
                if (depName === "require") {
                    args[i] = handlers.require(name);
                } else if (depName === "exports") {
                    //CommonJS module spec 1.1
                    args[i] = handlers.exports(name);
                    usingExports = true;
                } else if (depName === "module") {
                    //CommonJS module spec 1.1
                    cjsModule = args[i] = handlers.module(name);
                } else if (hasProp(defined, depName) ||
                           hasProp(waiting, depName) ||
                           hasProp(defining, depName)) {
                    args[i] = callDep(depName);
                } else if (map.p) {
                    map.p.load(map.n, makeRequire(relName, true), makeLoad(depName), {});
                    args[i] = defined[depName];
                } else {
                    throw new Error(name + ' missing ' + depName);
                }
            }

            ret = callback ? callback.apply(defined[name], args) : undefined;

            if (name) {
                //If setting exports via "module" is in play,
                //favor that over return value and exports. After that,
                //favor a non-undefined return value over exports use.
                if (cjsModule && cjsModule.exports !== undef &&
                        cjsModule.exports !== defined[name]) {
                    defined[name] = cjsModule.exports;
                } else if (ret !== undef || !usingExports) {
                    //Use the return value from the function.
                    defined[name] = ret;
                }
            }
        } else if (name) {
            //May just be an object definition for the module. Only
            //worry about defining if have a module name.
            defined[name] = callback;
        }
    };

    requirejs = require = req = function (deps, callback, relName, forceSync, alt) {
        if (typeof deps === "string") {
            if (handlers[deps]) {
                //callback in this case is really relName
                return handlers[deps](callback);
            }
            //Just return the module wanted. In this scenario, the
            //deps arg is the module name, and second arg (if passed)
            //is just the relName.
            //Normalize module name, if it contains . or ..
            return callDep(makeMap(deps, callback).f);
        } else if (!deps.splice) {
            //deps is a config object, not an array.
            config = deps;
            if (config.deps) {
                req(config.deps, config.callback);
            }
            if (!callback) {
                return;
            }

            if (callback.splice) {
                //callback is an array, which means it is a dependency list.
                //Adjust args if there are dependencies
                deps = callback;
                callback = relName;
                relName = null;
            } else {
                deps = undef;
            }
        }

        //Support require(['a'])
        callback = callback || function () {};

        //If relName is a function, it is an errback handler,
        //so remove it.
        if (typeof relName === 'function') {
            relName = forceSync;
            forceSync = alt;
        }

        //Simulate async callback;
        if (forceSync) {
            main(undef, deps, callback, relName);
        } else {
            //Using a non-zero value because of concern for what old browsers
            //do, and latest browsers "upgrade" to 4 if lower value is used:
            //http://www.whatwg.org/specs/web-apps/current-work/multipage/timers.html#dom-windowtimers-settimeout:
            //If want a value immediately, use require('id') instead -- something
            //that works in almond on the global level, but not guaranteed and
            //unlikely to work in other AMD implementations.
            setTimeout(function () {
                main(undef, deps, callback, relName);
            }, 4);
        }

        return req;
    };

    /**
     * Just drops the config on the floor, but returns req in case
     * the config return value is used.
     */
    req.config = function (cfg) {
        return req(cfg);
    };

    /**
     * Expose module registry for debugging and tooling
     */
    requirejs._defined = defined;

    define = function (name, deps, callback) {

        //This module may not have dependencies
        if (!deps.splice) {
            //deps is not an array, so probably means
            //an object literal or factory function for
            //the value. Adjust args.
            callback = deps;
            deps = [];
        }

        if (!hasProp(defined, name) && !hasProp(waiting, name)) {
            waiting[name] = [name, deps, callback];
        }
    };

    define.amd = {
        jQuery: true
    };
}());

define("almond", function(){});

define('cs',{load: function(id){throw new Error("Dynamic load not allowed: " + id);}});
define('underscore', [], function(){
  if(!this._) {
    console && console.error("Underscore has not been loaded into the page. Library will not work properly.")
  }
  return this._;
});

define('backbone', [], function(){
  if(!this.Backbone) {
    console && console.error("Backbone has not been loaded into the page. Library will not work properly.")
  }
  return this.Backbone;
});

// Backbone.Validation v0.9.2
//
// Copyright (c) 2011-2015 Thomas Pedersen
// Distributed under MIT License
//
// Documentation and full license available at:
// http://thedersen.com/projects/backbone-validation
(function (factory) {
  if (typeof exports === 'object') {
    module.exports = factory(require('backbone'), require('underscore'));
  } else if (typeof define === 'function' && define.amd) {
    define('backbone-validation',['backbone', 'underscore'], factory);
  }
}(function (Backbone, _) {
  Backbone.Validation = (function(_){
    'use strict';
  
    // Default options
    // ---------------
  
    var defaultOptions = {
      forceUpdate: false,
      selector: 'name',
      labelFormatter: 'sentenceCase',
      valid: Function.prototype,
      invalid: Function.prototype
    };
  
  
    // Helper functions
    // ----------------
  
    // Formatting functions used for formatting error messages
    var formatFunctions = {
      // Uses the configured label formatter to format the attribute name
      // to make it more readable for the user
      formatLabel: function(attrName, model) {
        return defaultLabelFormatters[defaultOptions.labelFormatter](attrName, model);
      },
  
      // Replaces nummeric placeholders like {0} in a string with arguments
      // passed to the function
      format: function() {
        var args = Array.prototype.slice.call(arguments),
            text = args.shift();
        return text.replace(/\{(\d+)\}/g, function(match, number) {
          return typeof args[number] !== 'undefined' ? args[number] : match;
        });
      }
    };
  
    // Flattens an object
    // eg:
    //
    //     var o = {
    //       address: {
    //         street: 'Street',
    //         zip: 1234
    //       }
    //     };
    //
    // becomes:
    //
    //     var o = {
    //       'address.street': 'Street',
    //       'address.zip': 1234
    //     };
    var flatten = function (obj, into, prefix) {
      into = into || {};
      prefix = prefix || '';
  
      _.each(obj, function(val, key) {
        if(obj.hasOwnProperty(key)) {
          if (!!val && typeof val === 'object' && val.constructor === Object) {
            flatten(val, into, prefix + key + '.');
          }
          else {
            into[prefix + key] = val;
          }
        }
      });
  
      return into;
    };
  
    // Validation
    // ----------
  
    var Validation = (function(){
  
      // Returns an object with undefined properties for all
      // attributes on the model that has defined one or more
      // validation rules.
      var getValidatedAttrs = function(model) {
        return _.reduce(_.keys(_.result(model, 'validation') || {}), function(memo, key) {
          memo[key] = void 0;
          return memo;
        }, {});
      };
  
      // Looks on the model for validations for a specified
      // attribute. Returns an array of any validators defined,
      // or an empty array if none is defined.
      var getValidators = function(model, attr) {
        var attrValidationSet = model.validation ? _.result(model, 'validation')[attr] || {} : {};
  
        // If the validator is a function or a string, wrap it in a function validator
        if (_.isFunction(attrValidationSet) || _.isString(attrValidationSet)) {
          attrValidationSet = {
            fn: attrValidationSet
          };
        }
  
        // Stick the validator object into an array
        if(!_.isArray(attrValidationSet)) {
          attrValidationSet = [attrValidationSet];
        }
  
        // Reduces the array of validators into a new array with objects
        // with a validation method to call, the value to validate against
        // and the specified error message, if any
        return _.reduce(attrValidationSet, function(memo, attrValidation) {
          _.each(_.without(_.keys(attrValidation), 'msg'), function(validator) {
            memo.push({
              fn: defaultValidators[validator],
              val: attrValidation[validator],
              msg: attrValidation.msg
            });
          });
          return memo;
        }, []);
      };
  
      // Validates an attribute against all validators defined
      // for that attribute. If one or more errors are found,
      // the first error message is returned.
      // If the attribute is valid, an empty string is returned.
      var validateAttr = function(model, attr, value, computed) {
        // Reduces the array of validators to an error message by
        // applying all the validators and returning the first error
        // message, if any.
        return _.reduce(getValidators(model, attr), function(memo, validator){
          // Pass the format functions plus the default
          // validators as the context to the validator
          var ctx = _.extend({}, formatFunctions, defaultValidators),
              result = validator.fn.call(ctx, value, attr, validator.val, model, computed);
  
          if(result === false || memo === false) {
            return false;
          }
          if (result && !memo) {
            return _.result(validator, 'msg') || result;
          }
          return memo;
        }, '');
      };
  
      // Loops through the model's attributes and validates them all.
      // Returns and object containing names of invalid attributes
      // as well as error messages.
      var validateModel = function(model, attrs) {
        var error,
            invalidAttrs = {},
            isValid = true,
            computed = _.clone(attrs),
            flattened = flatten(attrs);
  
        _.each(flattened, function(val, attr) {
          error = validateAttr(model, attr, val, computed);
          if (error) {
            invalidAttrs[attr] = error;
            isValid = false;
          }
        });
  
        return {
          invalidAttrs: invalidAttrs,
          isValid: isValid
        };
      };
  
      // Contains the methods that are mixed in on the model when binding
      var mixin = function(view, options) {
        return {
  
          // Check whether or not a value, or a hash of values
          // passes validation without updating the model
          preValidate: function(attr, value) {
            var self = this,
                result = {},
                error;
  
            if(_.isObject(attr)){
              _.each(attr, function(value, key) {
                error = self.preValidate(key, value);
                if(error){
                  result[key] = error;
                }
              });
  
              return _.isEmpty(result) ? undefined : result;
            }
            else {
              return validateAttr(this, attr, value, _.extend({}, this.attributes));
            }
          },
  
          // Check to see if an attribute, an array of attributes or the
          // entire model is valid. Passing true will force a validation
          // of the model.
          isValid: function(option) {
            var flattened = flatten(this.attributes);
  
            if(_.isString(option)){
              return !validateAttr(this, option, flattened[option], _.extend({}, this.attributes));
            }
            if(_.isArray(option)){
              return _.reduce(option, function(memo, attr) {
                return memo && !validateAttr(this, attr, flattened[attr], _.extend({}, this.attributes));
              }, true, this);
            }
            if(option === true) {
              this.validate();
            }
            return this.validation ? this._isValid : true;
          },
  
          // This is called by Backbone when it needs to perform validation.
          // You can call it manually without any parameters to validate the
          // entire model.
          validate: function(attrs, setOptions){
            var model = this,
                validateAll = !attrs,
                opt = _.extend({}, options, setOptions),
                validatedAttrs = getValidatedAttrs(model),
                allAttrs = _.extend({}, validatedAttrs, model.attributes, attrs),
                changedAttrs = flatten(attrs || allAttrs),
  
                result = validateModel(model, allAttrs);
  
            model._isValid = result.isValid;
  
            // After validation is performed, loop through all validated attributes
            // and call the valid callbacks so the view is updated.
            _.each(validatedAttrs, function(val, attr){
              var invalid = result.invalidAttrs.hasOwnProperty(attr);
              if(!invalid){
                opt.valid(view, attr, opt.selector);
              }
            });
  
            // After validation is performed, loop through all validated and changed attributes
            // and call the invalid callback so the view is updated.
            _.each(validatedAttrs, function(val, attr){
              var invalid = result.invalidAttrs.hasOwnProperty(attr),
                  changed = changedAttrs.hasOwnProperty(attr);
  
              if(invalid && (changed || validateAll)){
                opt.invalid(view, attr, result.invalidAttrs[attr], opt.selector);
              }
            });
  
            // Trigger validated events.
            // Need to defer this so the model is actually updated before
            // the event is triggered.
            _.defer(function() {
              model.trigger('validated', model._isValid, model, result.invalidAttrs);
              model.trigger('validated:' + (model._isValid ? 'valid' : 'invalid'), model, result.invalidAttrs);
            });
  
            // Return any error messages to Backbone, unless the forceUpdate flag is set.
            // Then we do not return anything and fools Backbone to believe the validation was
            // a success. That way Backbone will update the model regardless.
            if (!opt.forceUpdate && _.intersection(_.keys(result.invalidAttrs), _.keys(changedAttrs)).length > 0) {
              return result.invalidAttrs;
            }
          }
        };
      };
  
      // Helper to mix in validation on a model
      var bindModel = function(view, model, options) {
        _.extend(model, mixin(view, options));
      };
  
      // Removes the methods added to a model
      var unbindModel = function(model) {
        delete model.validate;
        delete model.preValidate;
        delete model.isValid;
      };
  
      // Mix in validation on a model whenever a model is
      // added to a collection
      var collectionAdd = function(model) {
        bindModel(this.view, model, this.options);
      };
  
      // Remove validation from a model whenever a model is
      // removed from a collection
      var collectionRemove = function(model) {
        unbindModel(model);
      };
  
      // Returns the public methods on Backbone.Validation
      return {
  
        // Current version of the library
        version: '0.9.1',
  
        // Called to configure the default options
        configure: function(options) {
          _.extend(defaultOptions, options);
        },
  
        // Hooks up validation on a view with a model
        // or collection
        bind: function(view, options) {
          options = _.extend({}, defaultOptions, defaultCallbacks, options);
  
          var model = options.model || view.model,
              collection = options.collection || view.collection;
  
          if(typeof model === 'undefined' && typeof collection === 'undefined'){
            throw 'Before you execute the binding your view must have a model or a collection.\n' +
                  'See http://thedersen.com/projects/backbone-validation/#using-form-model-validation for more information.';
          }
  
          if(model) {
            bindModel(view, model, options);
          }
          else if(collection) {
            collection.each(function(model){
              bindModel(view, model, options);
            });
            collection.bind('add', collectionAdd, {view: view, options: options});
            collection.bind('remove', collectionRemove);
          }
        },
  
        // Removes validation from a view with a model
        // or collection
        unbind: function(view, options) {
          options = _.extend({}, options);
          var model = options.model || view.model,
              collection = options.collection || view.collection;
  
          if(model) {
            unbindModel(model);
          }
          else if(collection) {
            collection.each(function(model){
              unbindModel(model);
            });
            collection.unbind('add', collectionAdd);
            collection.unbind('remove', collectionRemove);
          }
        },
  
        // Used to extend the Backbone.Model.prototype
        // with validation
        mixin: mixin(null, defaultOptions)
      };
    }());
  
  
    // Callbacks
    // ---------
  
    var defaultCallbacks = Validation.callbacks = {
  
      // Gets called when a previously invalid field in the
      // view becomes valid. Removes any error message.
      // Should be overridden with custom functionality.
      valid: function(view, attr, selector) {
        view.$('[' + selector + '~="' + attr + '"]')
            .removeClass('invalid')
            .removeAttr('data-error');
      },
  
      // Gets called when a field in the view becomes invalid.
      // Adds a error message.
      // Should be overridden with custom functionality.
      invalid: function(view, attr, error, selector) {
        view.$('[' + selector + '~="' + attr + '"]')
            .addClass('invalid')
            .attr('data-error', error);
      }
    };
  
  
    // Patterns
    // --------
  
    var defaultPatterns = Validation.patterns = {
      // Matches any digit(s) (i.e. 0-9)
      digits: /^\d+$/,
  
      // Matches any number (e.g. 100.000)
      number: /^-?(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d+)?$/,
  
      // Matches a valid email address (e.g. mail@example.com)
      email: /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i,
  
      // Mathes any valid url (e.g. http://www.xample.com)
      url: /^(https?|ftp):\/\/(((([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:)*@)?(((\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5]))|((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.?)(:\d*)?)(\/((([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)+(\/(([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)*)*)?)?(\?((([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)|[\uE000-\uF8FF]|\/|\?)*)?(\#((([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(%[\da-f]{2})|[!\$&'\(\)\*\+,;=]|:|@)|\/|\?)*)?$/i
    };
  
  
    // Error messages
    // --------------
  
    // Error message for the build in validators.
    // {x} gets swapped out with arguments form the validator.
    var defaultMessages = Validation.messages = {
      required: '{0} is required',
      acceptance: '{0} must be accepted',
      min: '{0} must be greater than or equal to {1}',
      max: '{0} must be less than or equal to {1}',
      range: '{0} must be between {1} and {2}',
      length: '{0} must be {1} characters',
      minLength: '{0} must be at least {1} characters',
      maxLength: '{0} must be at most {1} characters',
      rangeLength: '{0} must be between {1} and {2} characters',
      oneOf: '{0} must be one of: {1}',
      equalTo: '{0} must be the same as {1}',
      digits: '{0} must only contain digits',
      number: '{0} must be a number',
      email: '{0} must be a valid email',
      url: '{0} must be a valid url',
      inlinePattern: '{0} is invalid'
    };
  
    // Label formatters
    // ----------------
  
    // Label formatters are used to convert the attribute name
    // to a more human friendly label when using the built in
    // error messages.
    // Configure which one to use with a call to
    //
    //     Backbone.Validation.configure({
    //       labelFormatter: 'label'
    //     });
    var defaultLabelFormatters = Validation.labelFormatters = {
  
      // Returns the attribute name with applying any formatting
      none: function(attrName) {
        return attrName;
      },
  
      // Converts attributeName or attribute_name to Attribute name
      sentenceCase: function(attrName) {
        return attrName.replace(/(?:^\w|[A-Z]|\b\w)/g, function(match, index) {
          return index === 0 ? match.toUpperCase() : ' ' + match.toLowerCase();
        }).replace(/_/g, ' ');
      },
  
      // Looks for a label configured on the model and returns it
      //
      //      var Model = Backbone.Model.extend({
      //        validation: {
      //          someAttribute: {
      //            required: true
      //          }
      //        },
      //
      //        labels: {
      //          someAttribute: 'Custom label'
      //        }
      //      });
      label: function(attrName, model) {
        return (model.labels && model.labels[attrName]) || defaultLabelFormatters.sentenceCase(attrName, model);
      }
    };
  
  
    // Built in validators
    // -------------------
  
    var defaultValidators = Validation.validators = (function(){
      // Use native trim when defined
      var trim = String.prototype.trim ?
        function(text) {
          return text === null ? '' : String.prototype.trim.call(text);
        } :
        function(text) {
          var trimLeft = /^\s+/,
              trimRight = /\s+$/;
  
          return text === null ? '' : text.toString().replace(trimLeft, '').replace(trimRight, '');
        };
  
      // Determines whether or not a value is a number
      var isNumber = function(value){
        return _.isNumber(value) || (_.isString(value) && value.match(defaultPatterns.number));
      };
  
      // Determines whether or not a value is empty
      var hasValue = function(value) {
        return !(_.isNull(value) || _.isUndefined(value) || (_.isString(value) && trim(value) === '') || (_.isArray(value) && _.isEmpty(value)));
      };
  
      return {
        // Function validator
        // Lets you implement a custom function used for validation
        fn: function(value, attr, fn, model, computed) {
          if(_.isString(fn)){
            fn = model[fn];
          }
          return fn.call(model, value, attr, computed);
        },
  
        // Required validator
        // Validates if the attribute is required or not
        // This can be specified as either a boolean value or a function that returns a boolean value
        required: function(value, attr, required, model, computed) {
          var isRequired = _.isFunction(required) ? required.call(model, value, attr, computed) : required;
          if(!isRequired && !hasValue(value)) {
            return false; // overrides all other validators
          }
          if (isRequired && !hasValue(value)) {
            return this.format(defaultMessages.required, this.formatLabel(attr, model));
          }
        },
  
        // Acceptance validator
        // Validates that something has to be accepted, e.g. terms of use
        // `true` or 'true' are valid
        acceptance: function(value, attr, accept, model) {
          if(value !== 'true' && (!_.isBoolean(value) || value === false)) {
            return this.format(defaultMessages.acceptance, this.formatLabel(attr, model));
          }
        },
  
        // Min validator
        // Validates that the value has to be a number and equal to or greater than
        // the min value specified
        min: function(value, attr, minValue, model) {
          if (!isNumber(value) || value < minValue) {
            return this.format(defaultMessages.min, this.formatLabel(attr, model), minValue);
          }
        },
  
        // Max validator
        // Validates that the value has to be a number and equal to or less than
        // the max value specified
        max: function(value, attr, maxValue, model) {
          if (!isNumber(value) || value > maxValue) {
            return this.format(defaultMessages.max, this.formatLabel(attr, model), maxValue);
          }
        },
  
        // Range validator
        // Validates that the value has to be a number and equal to or between
        // the two numbers specified
        range: function(value, attr, range, model) {
          if(!isNumber(value) || value < range[0] || value > range[1]) {
            return this.format(defaultMessages.range, this.formatLabel(attr, model), range[0], range[1]);
          }
        },
  
        // Length validator
        // Validates that the value has to be a string with length equal to
        // the length value specified
        length: function(value, attr, length, model) {
          if (!_.isString(value) || value.length !== length) {
            return this.format(defaultMessages.length, this.formatLabel(attr, model), length);
          }
        },
  
        // Min length validator
        // Validates that the value has to be a string with length equal to or greater than
        // the min length value specified
        minLength: function(value, attr, minLength, model) {
          if (!_.isString(value) || value.length < minLength) {
            return this.format(defaultMessages.minLength, this.formatLabel(attr, model), minLength);
          }
        },
  
        // Max length validator
        // Validates that the value has to be a string with length equal to or less than
        // the max length value specified
        maxLength: function(value, attr, maxLength, model) {
          if (!_.isString(value) || value.length > maxLength) {
            return this.format(defaultMessages.maxLength, this.formatLabel(attr, model), maxLength);
          }
        },
  
        // Range length validator
        // Validates that the value has to be a string and equal to or between
        // the two numbers specified
        rangeLength: function(value, attr, range, model) {
          if (!_.isString(value) || value.length < range[0] || value.length > range[1]) {
            return this.format(defaultMessages.rangeLength, this.formatLabel(attr, model), range[0], range[1]);
          }
        },
  
        // One of validator
        // Validates that the value has to be equal to one of the elements in
        // the specified array. Case sensitive matching
        oneOf: function(value, attr, values, model) {
          if(!_.include(values, value)){
            return this.format(defaultMessages.oneOf, this.formatLabel(attr, model), values.join(', '));
          }
        },
  
        // Equal to validator
        // Validates that the value has to be equal to the value of the attribute
        // with the name specified
        equalTo: function(value, attr, equalTo, model, computed) {
          if(value !== computed[equalTo]) {
            return this.format(defaultMessages.equalTo, this.formatLabel(attr, model), this.formatLabel(equalTo, model));
          }
        },
  
        // Pattern validator
        // Validates that the value has to match the pattern specified.
        // Can be a regular expression or the name of one of the built in patterns
        pattern: function(value, attr, pattern, model) {
          if (!hasValue(value) || !value.toString().match(defaultPatterns[pattern] || pattern)) {
            return this.format(defaultMessages[pattern] || defaultMessages.inlinePattern, this.formatLabel(attr, model), pattern);
          }
        }
      };
    }());
  
    // Set the correct context for all validators
    // when used from within a method validator
    _.each(defaultValidators, function(validator, key){
      defaultValidators[key] = _.bind(defaultValidators[key], _.extend({}, formatFunctions, defaultValidators));
    });
  
    return Validation;
  }(_));
  return Backbone.Validation;
}));
/* global viewUtils */


/*
    Options:
        Validations: array containing validation descriptors:
            name:string - the name of the validator function to invoke
            failureMessage:string - the message passed to the callback when validation fails
            args:array - additional arguments to pass into the validation function
*/
define('xlform/view.utils.validator', [], function(){

return (function () {
    var singleton = {
            create: function (options) {
                return new Validator(options);
            },
            __validators: {
                invalidChars: function (value, chars) {
                    var matcher = new RegExp('[' + chars + ']');
                    return !matcher.test(value);
                },
                unique: function (value, list) {
                    return _.filter(list, function (item) { return item === value; }).length === 0;
                }
            }
        };

    
    var Validator = function (options) {
        this.options = options;
    };

    Validator.prototype.validate = function (value) {
        var validationsLength = this.options.validations.length,
            validations = this.options.validations;

        for (var i = 0; i < validationsLength; i++) {
            var currentValidation = validations[i];
            if (!currentValidation.args) {
                currentValidation.args = [];
            }
            currentValidation.args.unshift(value);

            if (!singleton.__validators[currentValidation.name].apply(this, currentValidation.args)) {
                return currentValidation.failureMessage;
            }
        }
        return true;
    };

    return singleton;
    
} ());

});


(function() {
  var __slice = [].slice;

  define('cs!xlform/view.utils', ['xlform/view.utils.validator'], function(Validator) {
    var viewUtils;

    viewUtils = {};
    viewUtils.Validator = Validator;
    viewUtils.makeEditable = function(that, model, selector, _arg) {
      var edit_callback, enable_edit, options, property, transformFunction;

      property = _arg.property, transformFunction = _arg.transformFunction, options = _arg.options, edit_callback = _arg.edit_callback;
      if (!(selector instanceof jQuery)) {
        selector = that.$el.find(selector);
      }
      if (selector.data('madeEditable')) {
        if (typeof console !== "undefined" && console !== null) {
          console.error("makeEditable called 2x on the same element: ", selector);
        }
      }
      selector.data('madeEditable', true);
      if (transformFunction == null) {
        transformFunction = function(value) {
          return value;
        };
      }
      if (property == null) {
        property = 'value';
      }
      if (edit_callback == null) {
        edit_callback = _.bind(function(ent) {
          ent = transformFunction(ent);
          ent = ent.replace(/\t/g, ' ');
          model.set(property, ent, {
            validate: true
          });
          if (model.validationError && model.validationError[property]) {
            return model.validationError[property];
          }
          return {
            newValue: ent
          };
        }, that);
      }
      selector.on('shown', function(e, obj) {
        return obj.input.$input.on('paste', function(e) {
          return e.stopPropagation();
        });
      });
      enable_edit = function() {
        var commit_edit, current_value, edit_box, parent_element;

        parent_element = selector.parent();
        parent_element.find('.error-message').remove();
        current_value = selector.text().replace(new RegExp(String.fromCharCode(160), 'g'), '');
        edit_box = $('<input />', {
          type: 'text',
          value: current_value,
          "class": 'js-cancel-sort js-blur-on-select-row'
        });
        selector.parent().append(edit_box);
        selector.hide();
        edit_box.focus();
        commit_edit = function() {
          var error_box, new_value;

          parent_element.find('.error-message').remove();
          if ((options != null) && (options.validate != null) && (options.validate(edit_box.val()) != null)) {
            new_value = options.validate(edit_box.val());
          } else {
            new_value = edit_callback(edit_box.val());
          }
          if (new_value == null) {
            new_value = {
              newValue: edit_box.val()
            };
          }
          if (new_value.newValue != null) {
            edit_box.remove();
            selector.show();
            return selector.html(new_value.newValue);
          } else {
            error_box = $('<div class="error-message">' + new_value + '</div>');
            return parent_element.append(error_box);
          }
        };
        edit_box.blur(commit_edit);
        return edit_box.keypress(function(event) {
          if (event.which === 13) {
            return commit_edit(event);
          }
        });
      };
      return selector.on('click', enable_edit);
    };
    viewUtils.reorderElemsByData = function(selector, parent, dataAttribute) {
      var $el, arr, parentEl, _i, _len;

      arr = [];
      parentEl = false;
      $(parent).find(selector).each(function(i) {
        var $el, val;

        if (i === 0) {
          parentEl = this.parentElement;
        } else if (this.parentElement !== parentEl) {
          throw new Error("All reordered items must be siblings");
        }
        $el = $(this).detach();
        val = $el.data(dataAttribute);
        if (_.isNumber(val)) {
          return arr[val] = $el;
        }
      });
      for (_i = 0, _len = arr.length; _i < _len; _i++) {
        $el = arr[_i];
        if ($el) {
          $el.appendTo(parentEl);
        }
      }
    };
    viewUtils.cleanStringify = function(atts) {
      var attArr, key, val;

      attArr = [];
      for (key in atts) {
        val = atts[key];
        if (val !== "") {
          attArr.push("<span class=\"atts\"><i>" + key + "</i>=\"<em>" + val + "</em>\"</span>");
        }
      }
      return attArr.join("&nbsp;");
    };
    viewUtils.debugFrame = (function() {
      var $div, debugFrameStyle, showFn;

      $div = false;
      debugFrameStyle = {
        position: "fixed",
        width: "95%",
        height: "80%",
        bottom: 10,
        left: "2.5%",
        overflow: "auto",
        zIndex: 100,
        backgroundColor: "rgba(255,255,255,0.7)"
      };
      showFn = function(txt) {
        var html;

        html = txt.split("\n").join("<br>");
        return $div = $("<div>", {
          "class": "well debug-frame"
        }).html("<code>" + html + "</code>").css(debugFrameStyle).appendTo("body");
      };
      showFn.close = function() {
        if ($div) {
          $div.remove();
          return $div = false;
        }
      };
      return showFn;
    })();
    viewUtils.launchQuestionLibrary = (function() {
      var launch;

      launch = function(opts) {
        var wrap;

        if (opts == null) {
          opts = {};
        }
        wrap = $("<div>", {
          "class": "js-click-remove-iframe iframe-bg-shade"
        });
        $("<div>").text("Launch question library in this element\n<section koboform-question-library=\"\"></section>").appendTo(wrap);
        wrap.click(function() {
          return wrap.remove();
        });
        return wrap;
      };
      return launch;
    })();
    viewUtils.enketoIframe = (function() {
      var buildUrl, clickCloserBackground, enketoPreviewUri, enketoServer, launch, _loadConfigs;

      enketoServer = "https://enketo.org";
      enketoPreviewUri = "/webform/preview";
      buildUrl = function(previewUrl) {
        return "" + enketoServer + enketoPreviewUri + "?form=" + previewUrl;
      };
      _loadConfigs = function(options) {
        if (options.enketoPreviewUri) {
          enketoPreviewUri = options.enketoPreviewUri;
        }
        if (options.enketoServer) {
          return enketoServer = options.enketoServer;
        }
      };
      clickCloserBackground = function() {
        return $("<div>", {
          "class": "js-click-remove-iframe"
        });
      };
      launch = function(previewUrl, options) {
        if (options == null) {
          options = {};
        }
        _loadConfigs(options);
        console.log(options);
        $(".enketo-holder").append($("<iframe>", {
          src: buildUrl(previewUrl)
        }));
        return $(".enketo-holder iframe").load(function() {
          return $(".enketo-loading-message").remove();
        });
      };
      launch.close = function() {
        $(".iframe-bg-shade").remove();
        return $(".enketo-holder").remove();
      };
      launch.fromCsv = function(surveyCsv, options) {
        var data, holder, onError, previewServer, wrap,
          _this = this;

        if (options == null) {
          options = {};
        }
        holder = $("<div>", {
          "class": "enketo-holder"
        }).html("<div class='enketo-iframe-icon'></div><div class=\"enketo-loading-message\"><p><i class=\"fa fa-spin fa-spinner\"></i><br/>Loading Preview</p><p>This will take a few seconds depending on the size of your form.</p></div>");
        wrap = $("<div>", {
          "class": "js-click-remove-iframe iframe-bg-shade"
        });
        holder.appendTo('body');
        wrap.appendTo('body');
        wrap.click(function() {
          wrap.remove();
          return holder.remove();
        });
        $('.enketo-holder .enketo-iframe-icon').click(function() {
          wrap.remove();
          return holder.remove();
        });
        previewServer = options.previewServer || "";
        data = JSON.stringify({
          body: surveyCsv
        });
        _loadConfigs(options);
        onError = options.onError || function() {
          var args;

          args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
          return typeof console !== "undefined" && console !== null ? console.error.apply(console, args) : void 0;
        };
        return $.ajax({
          url: "" + previewServer + "/koboform/survey_preview/",
          method: "POST",
          data: data,
          complete: function(jqhr, status) {
            var informative_message, response, unique_string;

            response = jqhr.responseJSON;
            if (status === "success" && response && response.unique_string) {
              unique_string = response.unique_string;
              launch("" + previewServer + "/koboform/survey_preview/" + unique_string);
              if (options.onSuccess != null) {
                return options.onSuccess();
              }
            } else if (status !== "success") {
              wrap.remove();
              holder.remove();
              informative_message = jqhr.responseText || jqhr.statusText;
              if (informative_message.split("\n").length > 0) {
                informative_message = informative_message.split("\n").slice(0, 3).join("<br>");
              }
              return onError(informative_message, {
                title: 'Error launching preview'
              });
            } else if (response && response.error) {
              wrap.remove();
              holder.remove();
              return onError(response.error);
            } else {
              wrap.remove();
              holder.remove();
              return onError("SurveyPreview response JSON is not recognized");
            }
          }
        });
      };
      return launch;
    })();
    viewUtils.ViewComposer = (function() {
      ViewComposer.prototype.add = function(view, id) {
        return this.views.push(view);
      };

      ViewComposer.prototype.remove = function(id) {
        throw 'not implemented';
      };

      ViewComposer.prototype.get = function(id) {
        throw 'not implemented';
      };

      ViewComposer.prototype.render = function() {
        var view, _i, _len, _ref, _results;

        _ref = this.views;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          view = _ref[_i];
          _results.push(view.render());
        }
        return _results;
      };

      ViewComposer.prototype.attach_to = function(destination) {
        var view, _i, _len, _ref, _results;

        _ref = this.views;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          view = _ref[_i];
          _results.push(view.attach_to(destination));
        }
        return _results;
      };

      ViewComposer.prototype.bind_event = function(event_name, callback) {
        throw 'not implemented';
      };

      function ViewComposer() {
        this.views = [];
      }

      return ViewComposer;

    })();
    return viewUtils;
  });

}).call(this);

define('xlform/model.validationLogicParserFactory', ['underscore'], function () {
    return function (equalityCriterionPattern, existenceCriterionPattern, criteriaJoinPattern, selectMultiplePattern) {
        function parseCriterion(text) {
            var matches = text.match(existenceCriterionPattern);
            if (matches === null) {
                matches = text.match(equalityCriterionPattern);
            }

            if (!!matches) {
                matches[2] = matches[2].replace(/\s+/, '').replace(/null/i, 'NULL');
            } else {
                return parseMultiselectCriterion(text);
            }

            var equalityMapper = {
                '=': 'resp_equals',
                '!=': 'resp_notequals',
                '>': 'resp_greater',
                '<': 'resp_less',
                '>=': 'resp_greaterequals',
                '<=': 'resp_lessequals',
                "!=''": 'ans_notnull',
                "=''": 'ans_null'
            };

            var res = {
                name: matches[1],
                operator: equalityMapper[matches[2]]
            };

            if (matches[3]) {
                res.response_value = matches[3].replace(/date\('(\d{4}-\d{2}-\d{2})'\)/, '$1');
            }

            return res;
        }

        function parseMultiselectCriterion(text) {
            var matches = text.match(selectMultiplePattern);

            if (!matches) {
                throw new Error('criterion not recognized: "' + text + '"');
            }

            return {
                name: matches[1],
                operator: text.indexOf('not(') == -1 ? 'multiplechoice_selected' : 'multiplechoice_notselected',
                response_value: matches[2]
            };
        }

        return function (text) {
            var criteria = text.split(criteriaJoinPattern),
                criteriaLength = criteria.length,
                joinOperators = text.match(criteriaJoinPattern);


            if (!!joinOperators && _.uniq(joinOperators).length > 1) {
                throw new Error('multiple criteria join operators are not supported at the moment');
            }

            if (criteriaLength === 1) {
                return {
                    criteria: [parseCriterion(text)]
                };
            } else {
                return {
                    criteria: _.map(criteria, function (criterion) {
                        return parseCriterion(criterion);
                    }),
                    operator: joinOperators[0].replace(/ /g, '').toUpperCase()
                };
            }
        };
    }
});


define('xlform/model.skipLogicParser', ['xlform/model.validationLogicParserFactory'], function($factory) {
    return $factory(/^\${(\w+)}\s*(=|!=|<|>|<=|>=)\s*\'?((?:date\(\'\d{4}-\d{2}-\d{2}\'\)|[\s\w]+|-?\d+)\.?\d*)\'?/,
                    /\${(\w+)}\s*((?:=|!=)\s*(?:NULL|''))/i,
                    / and | or /gi,
                    /selected\(\$\{(\w+)\},\s*\'(\w+)\'\)/);
});



define('xlform/model.validationLogicParser', ['xlform/model.validationLogicParserFactory'], function($factory) {
        return $factory(/(\.)\s*(=|!=|<|>|<=|>=)\s*\'?((?:date\(\'\d{4}-\d{2}-\d{2}\'\)|[\s\w]+|-?\d+)\.?\d*)\'?/,
                        /(\.)\s*((?:=|!=)\s*(?:NULL|''))/i,
                        / and | or /gi,
                        /selected\((\.)\s*,\s*\'(\w+)\'\)/);
});


(function() {
  var __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/model.utils', ['xlform/model.skipLogicParser', 'xlform/model.validationLogicParser'], function($skipLogicParser, $validationLogicParser) {
    var utils;

    utils = {
      skipLogicParser: $skipLogicParser,
      validationLogicParser: $validationLogicParser
    };
    utils.txtid = function() {
      var o;

      o = 'AAnCAnn'.replace(/[AaCn]/g, function(c) {
        var newI, r, randChar;

        randChar = function() {
          var charI;

          charI = Math.floor(Math.random() * 52);
          charI += (charI <= 25 ? 65 : 71);
          return String.fromCharCode(charI);
        };
        r = Math.random();
        if (c === 'a') {
          return randChar();
        } else if (c === 'A') {
          return String.fromCharCode(65 + (r * 26 | 0));
        } else if (c === 'C') {
          newI = Math.floor(r * 62);
          if (newI > 52) {
            return newI - 52;
          } else {
            return randChar();
          }
        } else if (c === 'n') {
          return Math.floor(r * 10);
        }
      });
      return o.toLowerCase();
    };
    utils.parseHelper = {
      parseSkipLogic: function(collection, value, parent_row) {
        var crit, e, opts, parsedValues, _i, _len, _ref;

        collection.meta.set("rawValue", value);
        try {
          parsedValues = $skipLogicParser(value);
          collection.reset();
          collection.parseable = true;
          _ref = parsedValues.criteria;
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            crit = _ref[_i];
            opts = {
              name: crit.name,
              expressionCode: crit.operator
            };
            if (crit.operator === "multiplechoice_selected") {
              opts.criterionOption = collection.getSurvey().findRowByName(crit.name).getList().options.get(crit.response_value);
            } else {
              opts.criterion = crit.response_value;
            }
            collection.add(opts, {
              silent: true,
              _parent: parent_row
            });
          }
          if (parsedValues.operator) {
            collection.meta.set("delimSelect", parsedValues.operator.toLowerCase());
          }
          return ;
        } catch (_error) {
          e = _error;
          return collection.parseable = false;
        }
      }
    };
    utils.sluggifyLabel = function(str, other_names) {
      if (other_names == null) {
        other_names = [];
      }
      return utils.sluggify(str, {
        preventDuplicates: other_names,
        lowerCase: false,
        preventDuplicateUnderscores: true,
        stripSpaces: true,
        lrstrip: true,
        incrementorPadding: 3,
        validXmlTag: true
      });
    };
    utils.isValidXmlTag = function(str) {
      return str.search(/^[a-zA-Z_:]([a-zA-Z0-9_:.])*$/) === 0;
    };
    utils.sluggify = function(str, opts) {
      var regex;

      if (opts == null) {
        opts = {};
      }
      if (str === '') {
        return '';
      }
      opts = _.defaults(opts, {
        lrstrip: false,
        lstrip: false,
        rstrip: false,
        descriptor: "slug",
        lowerCase: true,
        replaceNonWordCharacters: true,
        nonWordCharsExceptions: false,
        preventDuplicateUnderscores: false,
        validXmlTag: false,
        underscores: true,
        characterLimit: 30,
        preventDuplicates: false,
        incrementorPadding: false
      });
      if (opts.lrstrip) {
        opts.lstrip = true;
        opts.rstrip = true;
      }
      if (opts.lstrip) {
        str = str.replace(/^\s+/, "");
      }
      if (opts.rstrip) {
        str = str.replace(/\s+$/, "");
      }
      if (opts.lowerCase) {
        str = str.toLowerCase();
      }
      if (opts.underscores) {
        str = str.replace(/\s/g, "_").replace(/[_]+/g, "_");
      }
      if (opts.replaceNonWordCharacters) {
        if (opts.nonWordCharsExceptions) {
          regex = RegExp("\\W^[" + opts.nonWordCharsExceptions + "]", "g");
        } else {
          regex = /\W+/g;
        }
        str = str.replace(regex, '_');
        if (str.match(/._$/)) {
          str = str.replace(/_$/, '');
        }
      }
      if (_.isNumber(opts.characterLimit)) {
        str = str.slice(0, opts.characterLimit);
      }
      if (opts.validXmlTag) {
        if (str[0].match(/^\d/)) {
          str = "_" + str;
        }
      }
      if (opts.preventDuplicateUnderscores) {
        while (str.search(/__/) !== -1) {
          str = str.replace(/__/, '_');
        }
      }
      if (_.isArray(opts.preventDuplicates)) {
        str = (function() {
          var attempt, attempt_base, increment, increment_str, name, names_lc, _ref;

          names_lc = (function() {
            var _i, _len, _ref, _results;

            _ref = opts.preventDuplicates;
            _results = [];
            for (_i = 0, _len = _ref.length; _i < _len; _i++) {
              name = _ref[_i];
              if (name) {
                _results.push(name.toLowerCase());
              }
            }
            return _results;
          })();
          attempt_base = str;
          if (attempt_base.length === 0) {
            throw new Error("Renaming Error: " + opts.descriptor + " is empty");
          }
          attempt = attempt_base;
          increment = 0;
          while (_ref = attempt.toLowerCase(), __indexOf.call(names_lc, _ref) >= 0) {
            increment++;
            increment_str = "" + increment;
            if (opts.incrementorPadding && increment < Math.pow(10, opts.incrementorPadding)) {
              increment_str = ("000000000000" + increment).slice(-1 * opts.incrementorPadding);
            }
            attempt = "" + attempt_base + "_" + increment_str;
          }
          return attempt;
        })();
      }
      return str;
    };
    return utils;
  });

}).call(this);


/*
defaultSurveyDetails
--------------------
These values will be populated in the form builder and the user
will have the option to turn them on or off.

When exported, if the checkbox was selected, the "asJson" value
gets passed to the CSV builder and appended to the end of the
survey.

Details pulled from ODK documents / google docs. Notably this one:
  https://docs.google.com/spreadsheet/ccc?key=0AgpC5gsTSm_4dDRVOEprRkVuSFZUWTlvclJ6UFRvdFE#gid=0
*/


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/model.configs', ["underscore", 'cs!xlform/model.utils', "backbone"], function(_, $utils, Backbone) {
    var configs;

    configs = {};
    configs.defaultSurveyDetails = {
      start_time: {
        name: "start",
        label: "start time",
        description: "Records when the survey was begun",
        "default": true,
        asJson: {
          type: "start",
          name: "start"
        }
      },
      end_time: {
        name: "end",
        label: "end time",
        description: "tecords when the survey was marked as completed",
        "default": true,
        asJson: {
          type: "end",
          name: "end"
        }
      },
      today: {
        name: "today",
        label: "today",
        description: "includes today's date",
        "default": false,
        asJson: {
          type: "today",
          name: "today"
        }
      },
      username: {
        name: "username",
        label: "username",
        description: "includes interviewer's username",
        "default": false,
        asJson: {
          type: "username",
          name: "username"
        }
      },
      simserial: {
        name: "simserial",
        label: "sim serial",
        description: "records the serial number of the network sim card",
        "default": false,
        asJson: {
          type: "simserial",
          name: "simserial"
        }
      },
      subscriberid: {
        name: "subscriberid",
        label: "subscriber id",
        description: "records the subscriber id of the sim card",
        "default": false,
        asJson: {
          type: "subscriberid",
          name: "subscriberid"
        }
      },
      deviceid: {
        name: "deviceid",
        label: "device id",
        aliases: ["imei"],
        description: "Records the internal device ID number (works on Android phones)",
        "default": false,
        asJson: {
          type: "deviceid",
          name: "deviceid"
        }
      },
      phoneNumber: {
        name: "phonenumber",
        label: "phone number",
        description: "Records the device's phone number, when available",
        "default": false,
        asJson: {
          type: "phonenumber",
          name: "phonenumber"
        }
      }
    };
    (function() {
      var SurveyDetailSchemaItem, _ref, _ref1;

      SurveyDetailSchemaItem = (function(_super) {
        __extends(SurveyDetailSchemaItem, _super);

        function SurveyDetailSchemaItem() {
          _ref = SurveyDetailSchemaItem.__super__.constructor.apply(this, arguments);
          return _ref;
        }

        SurveyDetailSchemaItem.prototype._forSurvey = function() {
          return {
            name: this.get("name"),
            label: this.get("label"),
            description: this.get("description")
          };
        };

        return SurveyDetailSchemaItem;

      })(Backbone.Model);
      return configs.SurveyDetailSchema = (function(_super) {
        __extends(SurveyDetailSchema, _super);

        function SurveyDetailSchema() {
          _ref1 = SurveyDetailSchema.__super__.constructor.apply(this, arguments);
          return _ref1;
        }

        SurveyDetailSchema.prototype.model = SurveyDetailSchemaItem;

        SurveyDetailSchema.prototype.typeList = function() {
          var item;

          if (!this._typeList) {
            this._typeList = (function() {
              var _i, _len, _ref2, _results;

              _ref2 = this.models;
              _results = [];
              for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
                item = _ref2[_i];
                _results.push(item.get("name"));
              }
              return _results;
            }).call(this);
          }
          return this._typeList;
        };

        return SurveyDetailSchema;

      })(Backbone.Collection);
    })();
    configs.surveyDetailSchema = new configs.SurveyDetailSchema(_.values(configs.defaultSurveyDetails));
    /*
    Default values for rows of each question type
    */

    configs.defaultsForType = {
      geopoint: {
        label: {
          value: "Record your current location"
        },
        required: {
          value: false,
          _hideUnlessChanged: true
        }
      },
      image: {
        label: {
          value: "Point and shoot! Use the camera to take a photo"
        }
      },
      video: {
        label: {
          value: "Use the camera to record a video"
        }
      },
      audio: {
        label: {
          value: "Use the camera's microphone to record a sound"
        }
      },
      note: {
        label: {
          value: "This note can be read out loud"
        },
        required: {
          value: false,
          _hideUnlessChanged: true
        }
      },
      integer: {
        label: {
          value: "Enter a number"
        }
      },
      barcode: {
        label: {
          value: "Use the camera to scan a barcode"
        }
      },
      decimal: {
        label: {
          value: "Enter a number"
        }
      },
      date: {
        label: {
          value: "Enter a date"
        }
      },
      calculate: {
        calculation: {
          value: ""
        },
        label: {
          value: "calculation"
        },
        required: {
          value: false,
          _hideUnlessChanged: true
        }
      },
      datetime: {
        label: {
          value: "Enter a date and time"
        }
      },
      time: {
        label: {
          value: "Enter a time"
        }
      },
      acknowledge: {
        label: {
          value: "Acknowledge"
        }
      }
    };
    configs.columns = ["type", "name", "label", "hint", "required", "relevant", "default", "constraint"];
    configs.lookupRowType = (function() {
      var Type, arr, exp, typeLabels, types;

      typeLabels = [
        [
          "note", "Note", {
            preventRequired: true
          }
        ], ["acknowledge", "Acknowledge"], ["text", "Text"], ["integer", "Integer"], ["decimal", "Decimal"], ["geopoint", "Geopoint (GPS)"], [
          "image", "Image", {
            isMedia: true
          }
        ], ["barcode", "Barcode"], ["date", "Date"], ["time", "Time"], ["datetime", "Date and Time"], [
          "audio", "Audio", {
            isMedia: true
          }
        ], [
          "video", "Video", {
            isMedia: true
          }
        ], ["calculate", "Calculate"], [
          "select_one", "Select", {
            orOtherOption: true,
            specifyChoice: true
          }
        ], ["score", "Score"], ["score__row", "Score Row"], ["rank", "Rank"], ["rank__level", "Rank Level"], [
          "select_multiple", "Multiple choice", {
            orOtherOption: true,
            specifyChoice: true
          }
        ]
      ];
      Type = (function() {
        function Type(_arg) {
          var opts;

          this.name = _arg[0], this.label = _arg[1], opts = _arg[2];
          if (!opts) {
            opts = {};
          }
          _.extend(this, opts);
        }

        return Type;

      })();
      types = (function() {
        var _i, _len, _results;

        _results = [];
        for (_i = 0, _len = typeLabels.length; _i < _len; _i++) {
          arr = typeLabels[_i];
          _results.push(new Type(arr));
        }
        return _results;
      })();
      exp = function(typeId) {
        var output, tp, _i, _len;

        for (_i = 0, _len = types.length; _i < _len; _i++) {
          tp = types[_i];
          if (tp.name === typeId) {
            output = tp;
          }
        }
        return output;
      };
      exp.typeSelectList = (function() {
        return function() {
          return types;
        };
      })();
      return exp;
    })();
    configs.columnOrder = (function() {
      return function(key) {
        if (-1 === configs.columns.indexOf(key)) {
          configs.columns.push(key);
        }
        return configs.columns.indexOf(key);
      };
    })();
    configs.newRowDetails = {
      name: {
        value: ""
      },
      label: {
        value: "new question"
      },
      type: {
        value: "text"
      },
      hint: {
        value: "",
        _hideUnlessChanged: true
      },
      required: {
        value: true,
        _hideUnlessChanged: true
      },
      relevant: {
        value: "",
        _hideUnlessChanged: true
      },
      "default": {
        value: "",
        _hideUnlessChanged: true
      },
      constraint: {
        value: "",
        _hideUnlessChanged: true
      },
      constraint_message: {
        value: "",
        _hideUnlessChanged: true
      },
      appearance: {
        value: '',
        _hideUnlessChanged: true
      }
    };
    configs.newGroupDetails = {
      name: {
        value: function() {
          return "group_" + ($utils.txtid());
        }
      },
      label: {
        value: "Group"
      },
      type: {
        value: "group"
      },
      _isRepeat: {
        value: false
      },
      relevant: {
        value: "",
        _hideUnlessChanged: true
      },
      appearance: {
        value: '',
        _hideUnlessChanged: true
      }
    };
    configs.question_types = {};
    /*
    String representations of boolean values which are accepted as true from the XLSForm.
    */

    configs.truthyValues = ["yes", "true", "true()", "TRUE"];
    configs.falsyValues = ["no", "false", "false()", "FALSE"];
    configs.boolOutputs = {
      "true": "true",
      "false": "false"
    };
    return configs;
  });

}).call(this);


(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/mv.skipLogicHelpers', ['xlform/model.skipLogicParser'], function($skipLogicParser) {
    var operators, ops, skipLogicHelpers;

    skipLogicHelpers = {};
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    skipLogicHelpers.SkipLogicHelperFactory = (function() {
      function SkipLogicHelperFactory(model_factory, view_factory, survey, current_question, serialized_criteria) {
        this.model_factory = model_factory;
        this.view_factory = view_factory;
        this.survey = survey;
        this.current_question = current_question;
        this.serialized_criteria = serialized_criteria;
      }

      SkipLogicHelperFactory.prototype.create_presenter = function(criterion_model, criterion_view) {
        return new skipLogicHelpers.SkipLogicPresenter(criterion_model, criterion_view, this.current_question, this.survey, this.view_factory);
      };

      SkipLogicHelperFactory.prototype.create_builder = function() {
        return new skipLogicHelpers.SkipLogicBuilder(this.model_factory, this.view_factory, this.survey, this.current_question, this);
      };

      SkipLogicHelperFactory.prototype.create_context = function() {
        return new skipLogicHelpers.SkipLogicHelperContext(this.model_factory, this.view_factory, this, this.serialized_criteria);
      };

      return SkipLogicHelperFactory;

    })();
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    skipLogicHelpers.SkipLogicPresentationFacade = (function() {
      function SkipLogicPresentationFacade(model_factory, helper_factory, view_factory) {
        this.model_factory = model_factory;
        this.helper_factory = helper_factory;
        this.view_factory = view_factory;
      }

      SkipLogicPresentationFacade.prototype.initialize = function() {
        var _ref;

        return (_ref = this.context) != null ? _ref : this.context = this.helper_factory.create_context();
      };

      SkipLogicPresentationFacade.prototype.serialize = function() {
        var _ref;

        if ((_ref = this.context) == null) {
          this.context = this.helper_factory.create_context();
        }
        return this.context.serialize();
      };

      SkipLogicPresentationFacade.prototype.render = function(target) {
        var _ref;

        if ((_ref = this.context) == null) {
          this.context = this.helper_factory.create_context();
        }
        return this.context.render(target);
      };

      return SkipLogicPresentationFacade;

    })();
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    skipLogicHelpers.SkipLogicPresenter = (function() {
      function SkipLogicPresenter(model, view, current_question, survey, view_factory) {
        var update_choice_list,
          _this = this;

        this.model = model;
        this.view = view;
        this.current_question = current_question;
        this.survey = survey;
        this.view_factory = view_factory;
        this.view.presenter = this;
        if (this.survey) {
          update_choice_list = function(cid) {
            var current_response_value, options, question, response_picker_model;

            question = _this.model._get_question();
            if (question._isSelectQuestion() && question.getList().cid === cid) {
              current_response_value = _this.model.get('response_value').get('cid');
              if (!question.getList().options.get(current_response_value)) {
                return _this.dispatcher.trigger('remove:presenter', _this.model.cid);
              } else {
                options = _.map(question.getList().options.models, function(response) {
                  return {
                    text: response.get('label'),
                    value: response.cid
                  };
                });
                response_picker_model = _this.view.response_value_view.options;
                response_picker_model.set('options', options);
                _this.view.response_value_view.val(current_response_value);
                _this.view.response_value_view.$el.trigger('change');
                return _this.model.change_response(current_response_value);
              }
            }
          };
          this.survey.on('choice-list-update', update_choice_list, this);
          this.survey.on('remove-option', update_choice_list, this);
          this.survey.on('row-detail-change', function(row, key) {
            if (_this.destination) {
              if (key === 'label') {
                return _this.render(_this.destination);
              }
            }
          }, this);
        } else {
          console.error("this.survey is not yet available");
        }
      }

      SkipLogicPresenter.prototype.change_question = function(question_name) {
        var question_type,
          _this = this;

        this.model.change_question(question_name);
        this.question = this.model._get_question();
        question_type = this.question.get_type();
        this.question.on('remove', function() {
          return _this.dispatcher.trigger('remove:presenter', _this.model.cid);
        });
        this.view.change_operator(this.view_factory.create_operator_picker(question_type));
        this.view.operator_picker_view.val(this.model.get('operator').get_value());
        this.view.attach_operator();
        this.change_response_view(question_type, this.model.get('operator').get_type());
        return this.finish_changing();
      };

      SkipLogicPresenter.prototype.change_operator = function(operator_id) {
        this.model.change_operator(operator_id);
        this.change_response_view(this.model._get_question().get_type(), this.model.get('operator').get_type());
        return this.finish_changing();
      };

      SkipLogicPresenter.prototype.change_response = function(response_text) {
        this.model.change_response(response_text);
        return this.finish_changing();
      };

      SkipLogicPresenter.prototype.change_response_view = function(question_type, operator_type) {
        var question, response_value, response_view;

        response_view = this.view_factory.create_response_value_view(this.model._get_question(), question_type, operator_type);
        response_view.model = this.model.get('response_value');
        this.view.change_response(response_view);
        this.view.attach_response();
        response_value = response_view.model.get('value');
        question = this.model._get_question();
        if (question._isSelectQuestion()) {
          response_value = _.find(question.getList().options.models, function(option) {
            return option.get('name') === response_value;
          }).cid;
        }
        this.view.response_value_view.val(response_value);
        return response_view.$el.trigger('change');
      };

      SkipLogicPresenter.prototype.finish_changing = function() {
        return this.dispatcher.trigger('changed:model', this);
      };

      SkipLogicPresenter.prototype.is_valid = function() {
        var _ref;

        if (!this.model._get_question()) {
          return false;
        } else if (this.model.get('operator').get_type().id === 1) {
          return true;
        } else if (((_ref = this.model.get('response_value').get('value')) === '' || _ref === (void 0)) || this.model.get('response_value').isValid() === false) {
          return false;
        } else {
          return true;
        }
      };

      SkipLogicPresenter.prototype.render = function(destination) {
        var question, response_value, _ref, _ref1;

        this.destination = destination;
        this.view.question_picker_view.detach();
        this.view.question_picker_view = this.view_factory.create_question_picker(this.current_question);
        this.view.render();
        this.view.question_picker_view.val(this.model.get('question_cid'));
        this.view.operator_picker_view.val(this.model.get('operator').get_value());
        response_value = (_ref = this.model.get('response_value')) != null ? _ref.get('value') : void 0;
        question = this.model._get_question();
        if (question && question._isSelectQuestion()) {
          response_value = (_ref1 = _.find(question.getList().options.models, function(option) {
            return option.get('name') === response_value;
          })) != null ? _ref1.cid : void 0;
        }
        this.view.response_value_view.val(response_value);
        this.view.attach_to(destination);
        return this.dispatcher.trigger('rendered', this);
      };

      SkipLogicPresenter.prototype.serialize = function() {
        return this.model.serialize();
      };

      return SkipLogicPresenter;

    })();
    skipLogicHelpers.SkipLogicBuilder = (function() {
      function SkipLogicBuilder(model_factory, view_factory, survey, current_question, helper_factory) {
        this.model_factory = model_factory;
        this.view_factory = view_factory;
        this.survey = survey;
        this.current_question = current_question;
        this.helper_factory = helper_factory;
        this.build_empty_criterion = __bind(this.build_empty_criterion, this);
        this.build_criterion = __bind(this.build_criterion, this);
        this.build_operator_logic = __bind(this.build_operator_logic, this);
        return;
      }

      SkipLogicBuilder.prototype.build_criterion_builder = function(serialized_criteria) {
        var criteria, e, parsed,
          _this = this;

        if (serialized_criteria === '') {
          return [[this.build_empty_criterion()], 'and'];
        }
        try {
          parsed = this._parse_skip_logic_criteria(serialized_criteria);
          criteria = _.filter(_.map(parsed.criteria, function(criterion) {
            _this.criterion = criterion;
            return _this.build_criterion();
          }), function(item) {
            return !!item;
          });
          if (criteria.length === 0) {
            criteria.push(this.build_empty_criterion());
          }
        } catch (_error) {
          e = _error;
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.log("SkipLogic cell: " + serialized_criteria);
          }
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.error("could not parse skip logic. falling back to hand-coded");
          }
          return false;
        }
        return [criteria, parsed.operator];
      };

      SkipLogicBuilder.prototype._parse_skip_logic_criteria = function(criteria) {
        return $skipLogicParser(criteria);
      };

      SkipLogicBuilder.prototype.build_operator_logic = function(question_type) {
        return [this.build_operator_model(question_type, this._operator_type().symbol[this.criterion.operator]), this.view_factory.create_operator_picker(question_type)];
      };

      SkipLogicBuilder.prototype.build_operator_model = function(question_type, symbol) {
        var operator_type;

        operator_type = this._operator_type();
        return this.model_factory.create_operator((operator_type.type === 'existence' ? 'existence' : question_type.equality_operator_type), symbol, operator_type.id);
      };

      SkipLogicBuilder.prototype._operator_type = function() {
        var _this = this;

        return _.find(skipLogicHelpers.operator_types, function(op_type) {
          var _ref, _ref1;

          return _ref = (_ref1 = _this.criterion) != null ? _ref1.operator : void 0, __indexOf.call(op_type.parser_name, _ref) >= 0;
        });
      };

      SkipLogicBuilder.prototype.build_criterion_logic = function(operator_model, operator_picker_view, response_value_view) {
        var criterion_model, criterion_view;

        criterion_model = this.model_factory.create_criterion_model();
        criterion_model.set('operator', operator_model);
        criterion_view = this.view_factory.create_criterion_view(this.view_factory.create_question_picker(this.current_question), operator_picker_view, response_value_view);
        criterion_view.model = criterion_model;
        return this.helper_factory.create_presenter(criterion_model, criterion_view);
      };

      SkipLogicBuilder.prototype.build_criterion = function() {
        var operator_model, operator_picker_view, presenter, question, question_type, response_value, response_value_view, _ref, _ref1,
          _this = this;

        question = this._get_question();
        if (!question) {
          return false;
        }
        if (!(__indexOf.call(this.questions(), question) >= 0)) {
          throw 'question is not selectable';
        }
        question_type = question.get_type();
        _ref = this.build_operator_logic(question_type), operator_model = _ref[0], operator_picker_view = _ref[1];
        response_value_view = this.view_factory.create_response_value_view(question, question_type, this._operator_type());
        presenter = this.build_criterion_logic(operator_model, operator_picker_view, response_value_view);
        presenter.model.change_question(question.cid);
        response_value = question._isSelectQuestion() ? (_ref1 = _.find(question.getList().options.models, function(option) {
          return option.get('name') === _this.criterion.response_value;
        })) != null ? _ref1.cid : void 0 : this.criterion.response_value;
        presenter.model.change_response(response_value || '');
        response_value_view.model = presenter.model.get('response_value');
        response_value_view.val(response_value);
        return presenter;
      };

      SkipLogicBuilder.prototype._get_question = function() {
        return this.survey.findRowByName(this.criterion.name);
      };

      SkipLogicBuilder.prototype.build_empty_criterion = function() {
        var operator_picker_view, response_value_view;

        operator_picker_view = this.view_factory.create_operator_picker(null);
        response_value_view = this.view_factory.create_response_value_view(null);
        return this.build_criterion_logic(this.model_factory.create_operator('empty'), operator_picker_view, response_value_view);
      };

      SkipLogicBuilder.prototype.questions = function() {
        this.selectable = this.current_question.selectableRows() || this.selectable;
        return this.selectable;
      };

      return SkipLogicBuilder;

    })();
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    skipLogicHelpers.SkipLogicHelperContext = (function() {
      SkipLogicHelperContext.prototype.render = function(destination) {
        this.destination = destination;
        if (this.destination != null) {
          this.destination.empty();
          this.state.render(destination);
        }
      };

      SkipLogicHelperContext.prototype.serialize = function() {
        return this.state.serialize();
      };

      SkipLogicHelperContext.prototype.use_criterion_builder_helper = function() {
        var presenters, _ref;

        if ((_ref = this.builder) == null) {
          this.builder = this.helper_factory.create_builder();
        }
        presenters = this.builder.build_criterion_builder(this.state.serialize());
        if (presenters === false) {
          this.state = null;
        } else {
          this.state = new skipLogicHelpers.SkipLogicCriterionBuilderHelper(presenters[0], presenters[1], this.builder, this.view_factory, this);
          this.render(this.destination);
        }
      };

      SkipLogicHelperContext.prototype.use_hand_code_helper = function() {
        this.state = new skipLogicHelpers.SkipLogicHandCodeHelper(this.state.serialize(), this.builder, this.view_factory, this);
        this.render(this.destination);
      };

      SkipLogicHelperContext.prototype.use_mode_selector_helper = function() {
        this.helper_factory.survey.off(null, null, this.state);
        this.state = new skipLogicHelpers.SkipLogicModeSelectorHelper(this.view_factory, this);
        this.render(this.destination);
      };

      function SkipLogicHelperContext(model_factory, view_factory, helper_factory, serialized_criteria) {
        this.model_factory = model_factory;
        this.view_factory = view_factory;
        this.helper_factory = helper_factory;
        this.state = {
          serialize: function() {
            return serialized_criteria;
          }
        };
        if ((serialized_criteria == null) || serialized_criteria === '') {
          serialized_criteria = '';
          this.use_mode_selector_helper();
        } else {
          this.use_criterion_builder_helper();
        }
        if (this.state == null) {
          this.state = {
            serialize: function() {
              return serialized_criteria;
            }
          };
          this.use_hand_code_helper();
        }
      }

      return SkipLogicHelperContext;

    })();
    skipLogicHelpers.SkipLogicCriterionBuilderHelper = (function() {
      SkipLogicCriterionBuilderHelper.prototype.determine_criterion_delimiter_visibility = function() {
        if (this.presenters.length < 2) {
          return this.$criterion_delimiter.hide();
        } else {
          return this.$criterion_delimiter.show();
        }
      };

      SkipLogicCriterionBuilderHelper.prototype.render = function(destination) {
        var _this = this;

        this.view.render().attach_to(destination);
        this.$criterion_delimiter = this.view.$(".skiplogic__delimselect");
        this.$add_new_criterion_button = this.view.$('.skiplogic__addcriterion');
        this.determine_criterion_delimiter_visibility();
        this.destination = this.view.$('.skiplogic__criterialist');
        return _.each(this.presenters, function(presenter) {
          return presenter.render(_this.destination);
        });
      };

      SkipLogicCriterionBuilderHelper.prototype.serialize = function() {
        var serialized;

        serialized = _.map(this.presenters, function(presenter) {
          return presenter.serialize();
        });
        return _.filter(serialized, function(crit) {
          return crit;
        }).join(' ' + this.view.criterion_delimiter + ' ');
      };

      SkipLogicCriterionBuilderHelper.prototype.add_empty = function() {
        var presenter;

        presenter = this.builder.build_empty_criterion();
        presenter.dispatcher = this.dispatcher;
        presenter.serialize_all = _.bind(this.serialize, this);
        this.presenters.push(presenter);
        presenter.render(this.destination);
        return this.determine_criterion_delimiter_visibility();
      };

      SkipLogicCriterionBuilderHelper.prototype.remove = function(id) {
        var _this = this;

        _.each(this.presenters, function(presenter, index) {
          if ((presenter != null) && presenter.model.cid === id) {
            presenter = _this.presenters.splice(index, 1)[0];
            presenter.view.$el.remove();
            _this.builder.survey.off(null, null, presenter);
            return _this.determine_add_new_criterion_visibility();
          }
        });
        if (this.presenters.length === 0) {
          return this.context.use_mode_selector_helper();
        }
      };

      SkipLogicCriterionBuilderHelper.prototype.determine_add_new_criterion_visibility = function() {
        var action, _ref, _ref1;

        if (this.all_presenters_are_valid()) {
          action = 'show()';
          if ((_ref = this.$add_new_criterion_button) != null) {
            _ref.show();
          }
        } else {
          action = 'hide()';
          if ((_ref1 = this.$add_new_criterion_button) != null) {
            _ref1.hide();
          }
        }
        if (!this.$add_new_criterion_button) {
          return typeof trackJs !== "undefined" && trackJs !== null ? trackJs.console.error("@$add_new_criterion_button is not defined. cannot call " + action + " [inside of determine_add_new_criterion_visibility]") : void 0;
        }
      };

      function SkipLogicCriterionBuilderHelper(presenters, separator, builder, view_factory, context) {
        var removeInvalidPresenters,
          _this = this;

        this.presenters = presenters;
        this.builder = builder;
        this.view_factory = view_factory;
        this.context = context;
        this.view = this.view_factory.create_criterion_builder_view();
        this.view.criterion_delimiter = (separator || 'and').toLowerCase();
        this.view.facade = this;
        this.dispatcher = _.clone(Backbone.Events);
        this.dispatcher.on('remove:presenter', function(cid) {
          return _this.remove(cid);
        });
        this.dispatcher.on('changed:model', function(presenter) {
          return _this.determine_add_new_criterion_visibility();
        });
        this.dispatcher.on('rendered', function(presenter) {
          return _this.determine_add_new_criterion_visibility();
        });
        removeInvalidPresenters = function() {
          var presenter, presenters_to_be_removed, questions, _i, _len;

          questions = builder.questions();
          presenters_to_be_removed = [];
          _.each(_this.presenters, function(presenter) {
            var _ref;

            if (presenter.model._get_question() && !(_ref = presenter.model._get_question(), __indexOf.call(questions, _ref) >= 0)) {
              return presenters_to_be_removed.push(presenter.model.cid);
            }
          });
          for (_i = 0, _len = presenters_to_be_removed.length; _i < _len; _i++) {
            presenter = presenters_to_be_removed[_i];
            _this.remove(presenter);
          }
          if (_this.presenters.length === 0) {
            return _this.context.use_mode_selector_helper();
          }
        };
        this.builder.survey.on('sortablestop', removeInvalidPresenters, this);
        removeInvalidPresenters();
        _.each(this.presenters, function(presenter) {
          presenter.dispatcher = _this.dispatcher;
          return presenter.serialize_all = _.bind(_this.serialize, _this);
        });
      }

      SkipLogicCriterionBuilderHelper.prototype.all_presenters_are_valid = function() {
        return !_.find(this.presenters, function(presenter) {
          return !presenter.is_valid();
        });
      };

      SkipLogicCriterionBuilderHelper.prototype.switch_editing_mode = function() {
        return this.builder.build_hand_code_criteria(this.serialize());
      };

      return SkipLogicCriterionBuilderHelper;

    })();
    skipLogicHelpers.SkipLogicHandCodeHelper = (function() {
      SkipLogicHandCodeHelper.prototype.render = function($destination) {
        var _this = this;

        $destination.append(this.$parent);
        this.textarea.render().attach_to(this.$parent);
        this.button.render().attach_to(this.$parent);
        return this.button.bind_event('click', function() {
          return _this.context.use_mode_selector_helper();
        });
      };

      SkipLogicHandCodeHelper.prototype.serialize = function() {
        return this.textarea.$el.val() || this.criteria;
      };

      function SkipLogicHandCodeHelper(criteria, builder, view_factory, context) {
        this.criteria = criteria;
        this.builder = builder;
        this.view_factory = view_factory;
        this.context = context;
        this.$parent = $('<div>');
        this.textarea = this.view_factory.create_textarea(this.criteria, 'skiplogic__handcode-edit');
        this.button = this.view_factory.create_button('x', 'skiplogic-handcode__cancel');
      }

      return SkipLogicHandCodeHelper;

    })();
    skipLogicHelpers.SkipLogicModeSelectorHelper = (function() {
      SkipLogicModeSelectorHelper.prototype.render = function($destination) {
        var $parent,
          _this = this;

        $parent = $('<div>');
        $destination.append($parent);
        this.criterion_builder_button.render().attach_to($parent);
        this.handcode_button.render().attach_to($parent);
        this.criterion_builder_button.bind_event('click', function() {
          return _this.context.use_criterion_builder_helper();
        });
        return this.handcode_button.bind_event('click', function() {
          return _this.context.use_hand_code_helper();
        });
      };

      SkipLogicModeSelectorHelper.prototype.serialize = function() {
        return '';
      };

      function SkipLogicModeSelectorHelper(view_factory, context) {
        this.context = context;
        this.criterion_builder_button = view_factory.create_button('<i class="fa fa-plus"></i> Add a condition', 'skiplogic__button skiplogic__select-builder');
        this.handcode_button = view_factory.create_button('<i>${}</i> Manually enter your skip logic in XLSForm code', 'skiplogic__button skiplogic__select-handcode');
        /*@view = @view_factory.create_skip_logic_picker_view(context)
        */

      }

      SkipLogicModeSelectorHelper.prototype.switch_editing_mode = function() {};

      return SkipLogicModeSelectorHelper;

    })();
    operators = {
      EXISTENCE: 1,
      EQUALITY: 2,
      GREATER_THAN: 3,
      GREATER_THAN_EQ: 4
    };
    ops = {
      EX: operators.EXISTENCE,
      EQ: operators.EQUALITY,
      GT: operators.GREATER_THAN,
      GE: operators.GREATER_THAN_EQ
    };
    skipLogicHelpers.question_types = {
      "default": {
        operators: [ops.EX, ops.EQ],
        equality_operator_type: 'text',
        response_type: 'text',
        name: 'default'
      },
      select_one: {
        operators: [ops.EQ, ops.EX],
        equality_operator_type: 'text',
        response_type: 'dropdown',
        name: 'select_one'
      },
      select_multiple: {
        operators: [ops.EQ, ops.EX],
        equality_operator_type: 'select_multiple',
        response_type: 'dropdown',
        name: 'select_multiple'
      },
      integer: {
        operators: [ops.GT, ops.EX, ops.EQ, ops.GE],
        equality_operator_type: 'basic',
        response_type: 'integer',
        name: 'integer'
      },
      rank: {
        operators: [ops.EX, ops.EQ],
        equality_operator_type: 'select_multiple',
        response_type: 'dropdown',
        name: 'rank'
      },
      rank__item: {
        operators: [ops.EX, ops.EQ],
        equality_operator_type: 'select_multiple',
        response_type: 'dropdown',
        name: 'rank_item'
      },
      score: {
        operators: [ops.EX, ops.EQ],
        equality_operator_type: 'select_multiple',
        response_type: 'dropdown',
        name: 'score'
      },
      score__row: {
        operators: [ops.EX, ops.EQ],
        equality_operator_type: 'select_multiple',
        response_type: 'dropdown',
        name: 'score_row'
      },
      barcode: {
        operators: [ops.GT, ops.EX, ops.EQ, ops.GE],
        equality_operator_type: 'text',
        response_type: 'text',
        name: 'barcode'
      },
      decimal: {
        operators: [ops.EX, ops.EQ, ops.GT, ops.GE],
        equality_operator_type: 'basic',
        response_type: 'decimal',
        name: 'decimal'
      },
      geopoint: {
        operators: [ops.EX],
        name: 'geopoint'
      },
      image: {
        operators: [ops.EX],
        name: 'image'
      },
      audio: {
        operators: [ops.EX],
        name: 'audio'
      },
      video: {
        operators: [ops.EX],
        name: 'video'
      },
      acknowledge: {
        operators: [ops.EX],
        name: 'acknowledge'
      },
      date: {
        operators: [ops.EQ, ops.GT, ops.GE],
        equality_operator_type: 'date',
        response_type: 'text',
        name: 'date'
      }
    };
    skipLogicHelpers.operator_types = [
      {
        id: 1,
        type: 'existence',
        label: 'Was Answered',
        negated_label: 'Was not Answered',
        abbreviated_label: 'Was Answered',
        abbreviated_negated_label: 'Was not Answered',
        parser_name: ['ans_notnull', 'ans_null'],
        symbol: {
          ans_notnull: '!=',
          ans_null: '='
        },
        response_type: 'empty'
      }, {
        id: 2,
        type: 'equality',
        label: '',
        negated_label: 'not',
        abbreviated_label: '=',
        abbreviated_negated_label: '!=',
        parser_name: ['resp_equals', 'resp_notequals', 'multiplechoice_selected', 'multiplechoice_notselected'],
        symbol: {
          resp_equals: '=',
          resp_notequals: '!=',
          multiplechoice_selected: '=',
          multiplechoice_notselected: '!='
        }
      }, {
        id: 3,
        type: 'equality',
        label: 'Greater Than',
        negated_label: 'Less Than',
        abbreviated_label: '>',
        abbreviated_negated_label: '<',
        parser_name: ['resp_greater', 'resp_less'],
        symbol: {
          resp_greater: '>',
          resp_less: '<'
        }
      }, {
        id: 4,
        type: 'equality',
        label: 'Greater Than or Equal to',
        negated_label: 'Less Than or Equal to',
        abbreviated_label: '>=',
        abbreviated_negated_label: '<=',
        parser_name: ['resp_greaterequals', 'resp_lessequals'],
        symbol: {
          resp_greaterequals: '>=',
          resp_lessequals: '<='
        }
      }
    ];
    return skipLogicHelpers;
  });

}).call(this);

define('xlform/model.rowDetails.skipLogic', [
        'backbone',
        'cs!xlform/model.utils',
        'cs!xlform/mv.skipLogicHelpers'
        ], function(
                    Backbone,
                    $utils,
                    $skipLogicHelpers
                    ) {

var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

var rowDetailsSkipLogic = {};

  /**-----------------------------------------------------------------------------------------------------------
   * Factories.RowDetail.SkipLogic.coffee
   -----------------------------------------------------------------------------------------------------------**/

rowDetailsSkipLogic.SkipLogicFactory = (function() {
    SkipLogicFactory.prototype.create_operator = function(type, symbol, id) {
        var operator;
        switch (type) {
            case 'text':
                operator = new rowDetailsSkipLogic.TextOperator(symbol);
                break;
            case 'date':
                operator = new rowDetailsSkipLogic.DateOperator(symbol);
                break;
            case 'basic':
                operator = new rowDetailsSkipLogic.SkipLogicOperator(symbol);
                break;
            case 'existence':
                operator = new rowDetailsSkipLogic.ExistenceSkipLogicOperator(symbol);
                break;
            case 'select_multiple':
                operator = new rowDetailsSkipLogic.SelectMultipleSkipLogicOperator(symbol);
                break;
            case 'empty':
                return new rowDetailsSkipLogic.EmptyOperator();
        }
        operator.set('id', id);
        return operator;
    };

    SkipLogicFactory.prototype.create_criterion_model = function() {
        return new rowDetailsSkipLogic.SkipLogicCriterion(this, this.survey);
    };

    SkipLogicFactory.prototype.create_response_model = function(type) {
        var model;
        model = null;
        switch (type) {
            case 'integer':
                model = new rowDetailsSkipLogic.IntegerResponseModel;
                break;
            case 'decimal':
                model = new rowDetailsSkipLogic.DecimalResponseModel;
                break;
            default:
                model = new rowDetailsSkipLogic.ResponseModel(type);
        }
        return model.set('type', type);
    };

    function SkipLogicFactory(survey) {
        this.survey = survey;
    }

    return SkipLogicFactory;

})();

  /**-----------------------------------------------------------------------------------------------------------
   * Model.RowDetail.SkipLogic.Criterion.js
   -----------------------------------------------------------------------------------------------------------**/

rowDetailsSkipLogic.SkipLogicCriterion = (function(_super) {
    __extends(SkipLogicCriterion, _super);

    SkipLogicCriterion.prototype.serialize = function() {
        var response_model;
        response_model = this.get('response_value');
        if ((response_model != null) && (this.get('operator') != null) && (this.get('question_cid') != null) && response_model.isValid() !== false && (response_model.get('value') != null) && this._get_question()) {
            this._get_question().finalize();
            var questionName = this._get_question().getValue('name');
            return this.get('operator').serialize(questionName, response_model.get('value'));
        } else {
            return '';
        }
    };

    SkipLogicCriterion.prototype._get_question = function() {
        return this.survey.findRowByCid(this.get('question_cid'), { includeGroups: true });
    };

    SkipLogicCriterion.prototype.change_question = function(cid) {
        var old_question_type, question_type, _ref, _ref1, _ref2;
        old_question_type = ((_ref = this._get_question()) ? _ref.get_type() : void 0) || {
            name: null
        };
        this.set('question_cid', cid);
        question_type = this._get_question().get_type();
        if (_ref1 = this.get('operator').get_id(), __indexOf.call(question_type.operators, _ref1) < 0) {
            this.change_operator(question_type.operators[0]);
        } else if (old_question_type.name !== question_type.name) {
            this.change_operator(this.get('operator').get_value());
        }
        if ((this.get('operator').get_type().response_type == null) && this._get_question().response_type !== ((_ref2 = this.get('response_value')) != null ? _ref2.get_type() : void 0)) {
            return this.change_response((response_model = this.get('response_value')) != null ? (this._get_question()._isSelectQuestion() ? response_model.get('cid'): response_model.get('value')) : '');
        }
    };

    SkipLogicCriterion.prototype.change_operator = function(operator) {
        var is_negated, operator_model, question_type, symbol, type, _ref, _ref1;
        operator = +operator;
        is_negated = false;
        if (operator < 0) {
            is_negated = true;
            operator *= -1;
        }
        question_type = this._get_question().get_type();
        if (!(__indexOf.call(question_type.operators, operator) >= 0)) {
            return;
        }
        //get operator types
        type = $skipLogicHelpers.operator_types[operator - 1];
        symbol = type.symbol[type.parser_name[+is_negated]];
        operator_model = this.factory.create_operator((type.type === 'equality' ? question_type.equality_operator_type : type.type), symbol, operator);
        this.set('operator', operator_model);
        if ((type.response_type || question_type.response_type) !== ((_ref = this.get('response_value')) != null ? _ref.get('type') : void 0)) {
            return this.change_response(((_ref1 = this.get('response_value')) != null ? (this._get_question()._isSelectQuestion() ? _ref1.get('cid'): _ref1.get('value')) : void 0) || '');
        }
    };

    SkipLogicCriterion.prototype.get_correct_type = function() {
        return this.get('operator').get_type().response_type || this._get_question().get_type().response_type;
    };

    SkipLogicCriterion.prototype.set_option_names = function (options) {
            _.each(options, function(model) {
                if (model.get('name') == null) {
                    // get sluggify
                    return model.set('name', $utils.sluggify(model.get('label')));
                }
            });
    };

    SkipLogicCriterion.prototype.change_response = function(value) {
        var choice_cids, choices, current_value, response_model;
        response_model = this.get('response_value');
        if (!response_model || response_model.get('type') !== this.get_correct_type()) {
            response_model = this.factory.create_response_model(this.get_correct_type());
            this.set('response_value', response_model);
        }
        if (this.get_correct_type() === 'dropdown') {
            current_value = response_model ? response_model.get('cid') : null;

            var choicelist = this._get_question().getList();
            response_model.set('choicelist', choicelist);
            choices = choicelist.options.models;

            this.set_option_names(choices);

            choice_cids = _.map(choices, function(model) {
                return model.cid;
            });
            if (__indexOf.call(choice_cids, value) >= 0) {
                return response_model.set_value(value);
            } else if (__indexOf.call(choice_cids, current_value) >= 0) {
                return response_model.set_value(current_value);
            } else {
                return response_model.set_value(choices[0].cid);
            }
        } else {
            return response_model.set_value(value);
        }
    };

    function SkipLogicCriterion(factory, survey) {
        this.factory = factory;
        this.survey = survey;
        SkipLogicCriterion.__super__.constructor.call(this);
    }

    return SkipLogicCriterion;
})(Backbone.Model);

  /**-----------------------------------------------------------------------------------------------------------
   * Model.RowDetail.SkipLogic.Operators.js
   -----------------------------------------------------------------------------------------------------------**/

rowDetailsSkipLogic.Operator = (function(_super) {
    __extends(Operator, _super);

    function Operator() {
        return Operator.__super__.constructor.apply(this, arguments);
    }

    Operator.prototype.serialize = function(question_name, response_value) {
        throw new Error("Not Implemented");
    };

    Operator.prototype.get_value = function() {
        var val;
        val = '';
        if (this.get('is_negated')) {
            val = '-';
        }
        return val + this.get('id');
    };

    Operator.prototype.get_type = function() {
        // get operator types
        return $skipLogicHelpers.operator_types[this.get('id') - 1];
    };

    Operator.prototype.get_id = function() {
        return this.get('id');
    };

    return Operator;
    // get base model
})(Backbone.Model);

rowDetailsSkipLogic.EmptyOperator = (function(_super) {
    __extends(EmptyOperator, _super);

    EmptyOperator.prototype.serialize = function() {
        return '';
    };

    function EmptyOperator() {
        EmptyOperator.__super__.constructor.call(this);
        this.set('id', 0);
        this.set('is_negated', false);
    }

    return EmptyOperator;

})(rowDetailsSkipLogic.Operator);

rowDetailsSkipLogic.SkipLogicOperator = (function(_super) {
    __extends(SkipLogicOperator, _super);

    SkipLogicOperator.prototype.serialize = function(question_name, response_value) {
        return '${' + question_name + '} ' + this.get('symbol') + ' ' + response_value;
    };

    function SkipLogicOperator(symbol) {
        SkipLogicOperator.__super__.constructor.call(this);
        this.set('symbol', symbol);
        this.set('is_negated', ['!=', '<', '<='].indexOf(symbol) > -1);
    }

    return SkipLogicOperator;

})(rowDetailsSkipLogic.Operator);

rowDetailsSkipLogic.TextOperator = (function(_super) {
    __extends(TextOperator, _super);

    function TextOperator() {
        return TextOperator.__super__.constructor.apply(this, arguments);
    }

    TextOperator.prototype.serialize = function(question_name, response_value) {
        return TextOperator.__super__.serialize.call(this, question_name, "'" + response_value.replace(/'/g, "\\'") + "'");
    };

    return TextOperator;

})(rowDetailsSkipLogic.SkipLogicOperator);

rowDetailsSkipLogic.DateOperator = (function(_super) {
    __extends(DateOperator, _super);

    function DateOperator() {
        return DateOperator.__super__.constructor.apply(this, arguments);
    }

    DateOperator.prototype.serialize = function(question_name, response_value) {
        if (response_value.indexOf('date') == -1) {
            response_value = "date('" + response_value + "')"
        }
        return DateOperator.__super__.serialize.call(this, question_name, response_value);
    };

    return DateOperator;

})(rowDetailsSkipLogic.SkipLogicOperator);

rowDetailsSkipLogic.ExistenceSkipLogicOperator = (function(_super) {
    __extends(ExistenceSkipLogicOperator, _super);

    ExistenceSkipLogicOperator.prototype.serialize = function(question_name) {
        return ExistenceSkipLogicOperator.__super__.serialize.call(this, question_name, "''");
    };

    function ExistenceSkipLogicOperator(operator) {
        ExistenceSkipLogicOperator.__super__.constructor.call(this, operator);
        this.set('is_negated', operator === '=');
    }

    return ExistenceSkipLogicOperator;

})(rowDetailsSkipLogic.SkipLogicOperator);

rowDetailsSkipLogic.SelectMultipleSkipLogicOperator = (function(_super) {
    __extends(SelectMultipleSkipLogicOperator, _super);

    function SelectMultipleSkipLogicOperator() {
        return SelectMultipleSkipLogicOperator.__super__.constructor.apply(this, arguments);
    }

    SelectMultipleSkipLogicOperator.prototype.serialize = function(question_name, response_value) {
        var selected;
        selected = "selected(${" + question_name + "}, '" + response_value + "')";
        if (this.get('is_negated')) {
            return 'not(' + selected + ')';
        }
        return selected;
    };

    return SelectMultipleSkipLogicOperator;

})(rowDetailsSkipLogic.SkipLogicOperator);

  /**-----------------------------------------------------------------------------------------------------------
   * Model.RowDetail.SkipLogic.Responses.js
   -----------------------------------------------------------------------------------------------------------**/

rowDetailsSkipLogic.ResponseModel = (function(_super) {
    __extends(ResponseModel, _super);

    function ResponseModel(type) {
        ResponseModel.__super__.constructor.apply(this, []);
        if (type === 'dropdown') {
            this._set_value = this.set_value;
            this.set_value = function (cid) {
                var choice = this.get('choicelist').options.get(cid);
                if (choice) {
                    this._set_value(choice.get('name'));
                    this.set('cid', cid);
                }
            }
        }
    }

    ResponseModel.prototype.get_type = function() {
        return this.get('type');
    };

    ResponseModel.prototype.set_value = function(value) {
        return this.set('value', value, {
            validate: true
        });
    };

    return ResponseModel;
    // get base model
})(Backbone.Model);

rowDetailsSkipLogic.IntegerResponseModel = (function(_super) {
    __extends(IntegerResponseModel, _super);

    function IntegerResponseModel() {
        return IntegerResponseModel.__super__.constructor.apply(this, arguments);
    }

    IntegerResponseModel.prototype.validation = {
        value: {
            pattern: /^-?\d+$/,
            msg: 'Number must be integer'
        }
    };

    IntegerResponseModel.prototype.set_value = function(value) {
        if (value === ''){
            value = undefined;
        }
        return this.set('value', value, {
            validate: !!value
        });
    };

    return IntegerResponseModel;

})(rowDetailsSkipLogic.ResponseModel);

rowDetailsSkipLogic.DecimalResponseModel = (function(_super) {
    __extends(DecimalResponseModel, _super);

    function DecimalResponseModel() {
        return DecimalResponseModel.__super__.constructor.apply(this, arguments);
    }

    DecimalResponseModel.prototype.validation = {
        value: {
            pattern: 'number',
            msg: 'Number must be decimal'
        }
    };

    DecimalResponseModel.prototype.set_value = function(value) {
        function value_is_not_number() {
            return typeof value !== 'number';
        }

        if (typeof value === 'undefined' || value === '') {
            value = null;
        } else {
            if (value_is_not_number()) {
                value = value.replace(/\s/g, '');
                value = +value || value;
            }
            if (value_is_not_number()) {
                value = +(value.replace(',', '.')) || value;
            }
            if (value_is_not_number()) {
                if (value.lastIndexOf(',') > value.lastIndexOf('.')) {
                    value = +(value.replace(/\./g, '').replace(',', '.'));
                } else {
                    value = +(value.replace(',', ''));
                }
            }
        }
        return this.set('value', value, {
            validate: true
        });
    };

    return DecimalResponseModel;

})(rowDetailsSkipLogic.ResponseModel);

rowDetailsSkipLogic.DateResponseModel = (function(_super) {
    __extends(DateResponseModel, _super);

    function DateResponseModel() {
        return DateResponseModel.__super__.constructor.apply(this, arguments);
    }

    DateResponseModel.prototype.validation = {
        value: {
            pattern: /date\(\'\d{4}-\d{2}-\d{2}\'\)/
        }
    };

    DateResponseModel.prototype.set_value = function(value) {
        if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
            value = "date('" + value + "')";
        }
        return this.set('value', value, {
            validate: true
        });
    };

    return DateResponseModel;

})(rowDetailsSkipLogic.ResponseModel);

return rowDetailsSkipLogic;

});


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  define('cs!xlform/view.widgets', ['backbone'], function(Backbone) {
    var viewWidgets, _ref, _ref1, _ref2;

    viewWidgets = {};
    viewWidgets.Base = (function(_super) {
      __extends(Base, _super);

      function Base() {
        _ref = Base.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Base.prototype.attach_to = function($el) {
        if ($el instanceof viewWidgets.Base) {
          $el = $el.$el;
        }
        return $el.append(this.el);
      };

      Base.prototype.bind_event = function(type, callback) {
        this.$el.off(type, callback);
        return this.$el.on(type, callback);
      };

      Base.prototype.detach = function() {
        return this.$el.remove();
      };

      Base.prototype.val = function(value) {
        if (value) {
          this.$el.val(value);
          if (this.$el.val() == null) {
            return this.$el.prop('selectedIndex', 0);
          }
        } else {
          return this.$el.val();
        }
      };

      return Base;

    })(Backbone.View);
    viewWidgets.Label = (function(_super) {
      __extends(Label, _super);

      Label.prototype.tagName = 'label';

      function Label(text, className, input) {
        this.text = text;
        this.className = className;
        this.input = input;
        Label.__super__.constructor.call(this);
      }

      Label.prototype.val = function() {};

      Label.prototype.bind_event = function() {};

      Label.prototype.render = function() {
        if (this.text) {
          this.$el.text(this.text);
        }
        if (this.className) {
          this.$el.addClass(this.className);
        }
        if (this.input) {
          this.$el.attr('for', this.input.cid);
        }
        return this;
      };

      return Label;

    })(viewWidgets.Base);
    viewWidgets.EmptyView = (function(_super) {
      __extends(EmptyView, _super);

      function EmptyView() {
        _ref1 = EmptyView.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      EmptyView.prototype.attach_to = function() {};

      EmptyView.prototype.val = function() {};

      EmptyView.prototype.bind_event = function() {};

      EmptyView.prototype.render = function() {
        return this;
      };

      EmptyView.prototype.val = function() {
        return null;
      };

      return EmptyView;

    })(viewWidgets.Base);
    viewWidgets.TextArea = (function(_super) {
      __extends(TextArea, _super);

      TextArea.prototype.tagName = 'textarea';

      TextArea.prototype.render = function() {
        this.$el.val(this.text);
        this.$el.addClass(this.className);
        this.$el.on('paste', function(e) {
          return e.stopPropagation();
        });
        return this;
      };

      function TextArea(text, className) {
        this.text = text;
        this.className = className;
        TextArea.__super__.constructor.call(this);
      }

      return TextArea;

    })(viewWidgets.Base);
    viewWidgets.TextBox = (function(_super) {
      __extends(TextBox, _super);

      TextBox.prototype.tagName = 'input';

      TextBox.prototype.render = function() {
        this.$el.attr('type', 'text');
        this.$el.val(this.text);
        this.$el.addClass(this.className);
        this.$el.attr('placeholder', this.placeholder);
        this.$el.on('paste', function(e) {
          return e.stopPropagation();
        });
        return this;
      };

      function TextBox(text, className, placeholder) {
        this.text = text;
        this.className = className;
        this.placeholder = placeholder;
        TextBox.__super__.constructor.call(this);
      }

      return TextBox;

    })(viewWidgets.Base);
    viewWidgets.Button = (function(_super) {
      __extends(Button, _super);

      Button.prototype.tagName = 'button';

      Button.prototype.render = function() {
        this.$el.html(this.text);
        this.$el.addClass(this.className);
        return this;
      };

      function Button(text, className) {
        this.text = text;
        this.className = className;
        Button.__super__.constructor.call(this);
      }

      return Button;

    })(viewWidgets.Base);
    viewWidgets.DropDownModel = (function(_super) {
      __extends(DropDownModel, _super);

      function DropDownModel() {
        _ref2 = DropDownModel.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      return DropDownModel;

    })(Backbone.Model);
    viewWidgets.DropDown = (function(_super) {
      __extends(DropDown, _super);

      DropDown.prototype.tagName = 'select';

      function DropDown(options) {
        this.options = options;
        this.render = __bind(this.render, this);
        DropDown.__super__.constructor.apply(this, arguments);
        if (!(this.options instanceof viewWidgets.DropDownModel)) {
          this.options = new viewWidgets.DropDownModel();
          this.options.set('options', options);
        }
        this.options.on('change:options', this.render.bind(this));
      }

      DropDown.prototype.render = function() {
        var options;

        options = '';
        _.each(this.options.get('options'), function(option) {
          return options += '<option value="' + option.value + '">' + option.text + '</option>';
        });
        this.$el.html(options);
        return this;
      };

      DropDown.prototype.attach_to = function(target) {
        DropDown.__super__.attach_to.call(this, target);
        return this.$el.select2({
          minimumResultsForSearch: -1
        });
      };

      return DropDown;

    })(viewWidgets.Base);
    return viewWidgets;
  });

}).call(this);


(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/view.rowDetail.SkipLogic', ['backbone', 'xlform/model.rowDetails.skipLogic', 'cs!xlform/view.widgets', 'cs!xlform/mv.skipLogicHelpers'], function(Backbone, $modelRowDetailsSkipLogic, $viewWidgets, $skipLogicHelpers) {
    var viewRowDetailSkipLogic, _ref, _ref1, _ref2, _ref3;

    viewRowDetailSkipLogic = {};
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    viewRowDetailSkipLogic.SkipLogicCriterionBuilderView = (function(_super) {
      __extends(SkipLogicCriterionBuilderView, _super);

      function SkipLogicCriterionBuilderView() {
        this.addCriterion = __bind(this.addCriterion, this);        _ref = SkipLogicCriterionBuilderView.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      SkipLogicCriterionBuilderView.prototype.events = {
        "click .skiplogic__deletecriterion": "deleteCriterion",
        "click .skiplogic__addcriterion": "addCriterion",
        "change .skiplogic__delimselect": "markChangedDelimSelector"
      };

      SkipLogicCriterionBuilderView.prototype.render = function() {
        var delimSelect, tempId;

        tempId = _.uniqueId("skiplogic_expr");
        this.$el.html("<p>\n  This question will only be displayed if the following conditions apply\n</p>\n<div class=\"skiplogic__criterialist\"></div>\n<p class=\"skiplogic__addnew\">\n  <button class=\"skiplogic__addcriterion\">+ Add another condition</button>\n</p>\n<select class=\"skiplogic__delimselect\">\n  <option value=\"and\">Question should match all of these criteria</option>\n  <option value=\"or\">Question should match any of these criteria</option>\n</select>");
        delimSelect = this.$(".skiplogic__delimselect").val(this.criterion_delimiter);
        delimSelect.children('[value=' + this.criterion_delimiter + ']').attr('selected', 'selected');
        return this;
      };

      SkipLogicCriterionBuilderView.prototype.addCriterion = function(evt) {
        return this.facade.add_empty();
      };

      SkipLogicCriterionBuilderView.prototype.deleteCriterion = function(evt) {
        var $target, modelId;

        $target = $(evt.target);
        modelId = $target.data("criterionId");
        this.facade.remove(modelId);
        return $target.parent().remove();
      };

      SkipLogicCriterionBuilderView.prototype.markChangedDelimSelector = function(evt) {
        return this.criterion_delimiter = evt.target.value;
      };

      return SkipLogicCriterionBuilderView;

    })($viewWidgets.Base);
    viewRowDetailSkipLogic.SkipLogicCriterion = (function(_super) {
      __extends(SkipLogicCriterion, _super);

      SkipLogicCriterion.prototype.tagName = 'div';

      SkipLogicCriterion.prototype.className = 'skiplogic__criterion';

      SkipLogicCriterion.prototype.render = function() {
        this.question_picker_view.render();
        if (!this.alreadyRendered) {
          this.$el.append($("<i class=\"skiplogic__deletecriterion fa fa-trash-o\" data-criterion-id=\"" + this.model.cid + "\"></i>"));
        }
        this.change_operator(this.operator_picker_view);
        this.change_response(this.response_value_view);
        this.alreadyRendered = true;
        return this;
      };

      SkipLogicCriterion.prototype.mark_question_specified = function(is_specified) {
        if (is_specified == null) {
          is_specified = false;
        }
        return this.$el.toggleClass("skiplogic__criterion--unspecified-question", !is_specified);
      };

      SkipLogicCriterion.prototype.bind_question_picker = function() {
        var _this = this;

        this.mark_question_specified(+this.$question_picker.val() !== -1);
        return this.$question_picker.on('change', function(e) {
          _this.mark_question_specified(true);
          return _this.presenter.change_question(e.val);
        });
      };

      SkipLogicCriterion.prototype.bind_operator_picker = function() {
        var _this = this;

        return this.$operator_picker.on('change', function() {
          _this.operator_picker_view.value = _this.$operator_picker.select2('val');
          return _this.presenter.change_operator(_this.operator_picker_view.value);
        });
      };

      SkipLogicCriterion.prototype.bind_response_value = function() {
        var _this = this;

        return this.response_value_view.bind_event(function() {
          return _this.presenter.change_response(_this.response_value_view.val());
        });
      };

      SkipLogicCriterion.prototype.response_value_handler = function() {
        return this.presenter.change_response(this.response_value_view.val());
      };

      SkipLogicCriterion.prototype.change_operator = function(operator_picker_view) {
        this.operator_picker_view = operator_picker_view;
        this.operator_picker_view.render();
        return this.$operator_picker = this.operator_picker_view.$el;
      };

      SkipLogicCriterion.prototype.change_response = function(response_value_view) {
        this.response_value_view.detach();
        this.response_value_view = response_value_view;
        this.response_value_view.render();
        return this.$response_value = this.response_value_view.$el;
      };

      SkipLogicCriterion.prototype.attach_operator = function() {
        this.operator_picker_view.attach_to(this.$el);
        return this.bind_operator_picker();
      };

      SkipLogicCriterion.prototype.attach_response = function() {
        if (this.$('.skiplogic__responseval-wrapper').length > 0) {
          this.$('.skiplogic__responseval-wrapper').remove();
        }
        this.response_value_view.attach_to(this.$el);
        return this.bind_response_value();
      };

      SkipLogicCriterion.prototype.attach_to = function(element) {
        this.question_picker_view.attach_to(this.$el);
        this.$question_picker = this.question_picker_view.$el;
        this.bind_question_picker();
        this.attach_operator();
        this.attach_response();
        return SkipLogicCriterion.__super__.attach_to.apply(this, arguments);
      };

      function SkipLogicCriterion(question_picker_view, operator_picker_view, response_value_view, presenter) {
        this.question_picker_view = question_picker_view;
        this.operator_picker_view = operator_picker_view;
        this.response_value_view = response_value_view;
        this.presenter = presenter;
        SkipLogicCriterion.__super__.constructor.call(this);
      }

      return SkipLogicCriterion;

    })($viewWidgets.Base);
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    viewRowDetailSkipLogic.QuestionPicker = (function(_super) {
      __extends(QuestionPicker, _super);

      function QuestionPicker() {
        _ref1 = QuestionPicker.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      QuestionPicker.prototype.tagName = 'select';

      QuestionPicker.prototype.className = 'skiplogic__rowselect';

      QuestionPicker.prototype.render = function() {
        var _this = this;

        QuestionPicker.__super__.render.apply(this, arguments);
        this.$el.on('change', function() {
          return _this.$el.children(':first').prop('disabled', true);
        });
        return this;
      };

      QuestionPicker.prototype.attach_to = function(target) {
        target.find('.skiplogic__rowselect').remove();
        return QuestionPicker.__super__.attach_to.call(this, target);
      };

      return QuestionPicker;

    })($viewWidgets.DropDown);
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    viewRowDetailSkipLogic.OperatorPicker = (function(_super) {
      __extends(OperatorPicker, _super);

      OperatorPicker.prototype.tagName = 'div';

      OperatorPicker.prototype.className = 'skiplogic__expressionselect';

      OperatorPicker.prototype.render = function() {
        return this;
      };

      OperatorPicker.prototype.attach_to = function(target) {
        var _this = this;

        target.find('.skiplogic__expressionselect').remove();
        OperatorPicker.__super__.attach_to.call(this, target);
        this.$el.select2({
          minimumResultsForSearch: -1,
          data: (function() {
            var operators;

            operators = [];
            _.each(_this.operators, function(operator) {
              operators.push({
                id: operator.id,
                text: operator.label + (operator.id !== 1 ? ' (' + operator.symbol[operator.parser_name[0]] + ')' : '')
              });
              return operators.push({
                id: '-' + operator.id,
                text: operator.negated_label + (operator.id !== 1 ? ' (' + operator.symbol[operator.parser_name[1]] + ')' : '')
              });
            });
            return operators;
          })()
        });
        if (this.value) {
          this.val(this.value);
        } else {
          this.value = this.$el.select2('val');
        }
        return this.$el.on('select2-close', function() {
          return _this._set_style();
        });
      };

      OperatorPicker.prototype.val = function(value) {
        if (value != null) {
          this.$el.select2('val', value);
          this._set_style();
          return this.value = value;
        } else {
          return this.$el.val();
        }
      };

      OperatorPicker.prototype._set_style = function() {
        var abbreviated_label, absolute_value, chosen_element, operator, _ref2;

        this.$el.toggleClass('skiplogic__expressionselect--no-response-value', (_ref2 = +this.$el.val()) === (-1) || _ref2 === 1);
        absolute_value = this.$el.val() >= 0 ? +this.$el.val() : -this.$el.val();
        if (absolute_value === 0) {
          return;
        }
        operator = _.find(this.operators, function(operator) {
          return operator.id === absolute_value;
        });
        abbreviated_label = operator['abbreviated_' + (+this.$el.val() < 0 ? 'negated_' : '') + 'label'];
        chosen_element = this.$el.parents('.skiplogic__criterion').find('.select2-container.skiplogic__expressionselect .select2-chosen');
        return chosen_element.text(abbreviated_label);
      };

      function OperatorPicker(operators) {
        this.operators = operators;
        OperatorPicker.__super__.constructor.call(this);
      }

      return OperatorPicker;

    })($viewWidgets.Base);
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    viewRowDetailSkipLogic.SkipLogicEmptyResponse = (function(_super) {
      __extends(SkipLogicEmptyResponse, _super);

      function SkipLogicEmptyResponse() {
        _ref2 = SkipLogicEmptyResponse.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      SkipLogicEmptyResponse.prototype.className = 'skiplogic__responseval';

      SkipLogicEmptyResponse.prototype.attach_to = function(target) {
        target.find('.skiplogic__responseval').remove();
        return SkipLogicEmptyResponse.__super__.attach_to.call(this, target);
      };

      return SkipLogicEmptyResponse;

    })($viewWidgets.EmptyView);
    viewRowDetailSkipLogic.SkipLogicTextResponse = (function(_super) {
      __extends(SkipLogicTextResponse, _super);

      SkipLogicTextResponse.prototype.attach_to = function(target) {
        target.find('.skiplogic__responseval').remove();
        return SkipLogicTextResponse.__super__.attach_to.apply(this, arguments);
      };

      SkipLogicTextResponse.prototype.bind_event = function(handler) {
        return this.$el.on('blur', handler);
      };

      function SkipLogicTextResponse(text) {
        SkipLogicTextResponse.__super__.constructor.call(this, text, "skiplogic__responseval", "response value");
      }

      return SkipLogicTextResponse;

    })($viewWidgets.TextBox);
    viewRowDetailSkipLogic.SkipLogicValidatingTextResponseView = (function(_super) {
      __extends(SkipLogicValidatingTextResponseView, _super);

      function SkipLogicValidatingTextResponseView() {
        this.val = __bind(this.val, this);
        this.clear_invalid_view = __bind(this.clear_invalid_view, this);
        this.show_invalid_view = __bind(this.show_invalid_view, this);        _ref3 = SkipLogicValidatingTextResponseView.__super__.constructor.apply(this, arguments);
        return _ref3;
      }

      SkipLogicValidatingTextResponseView.prototype.render = function() {
        SkipLogicValidatingTextResponseView.__super__.render.apply(this, arguments);
        this.setElement('<div class="skiplogic__responseval-wrapper">' + this.$el + '<div></div></div>');
        this.$error_message = this.$('div');
        this.model.bind('validated:invalid', this.show_invalid_view);
        this.model.bind('validated:valid', this.clear_invalid_view);
        this.$input = this.$el.find('input');
        return this;
      };

      SkipLogicValidatingTextResponseView.prototype.show_invalid_view = function(model, errors) {
        if (this.$input.val()) {
          this.$el.addClass('textbox--invalid');
          this.$error_message.html(errors.value);
          return this.$input.focus();
        }
      };

      SkipLogicValidatingTextResponseView.prototype.clear_invalid_view = function(model, errors) {
        this.$el.removeClass('textbox--invalid');
        return this.$error_message.html('');
      };

      SkipLogicValidatingTextResponseView.prototype.bind_event = function(handler) {
        return this.$input.on('change', handler);
      };

      SkipLogicValidatingTextResponseView.prototype.val = function(value) {
        if (value != null) {
          return this.$input.val(value);
        } else {
          return this.$input.val();
        }
      };

      return SkipLogicValidatingTextResponseView;

    })(viewRowDetailSkipLogic.SkipLogicTextResponse);
    viewRowDetailSkipLogic.SkipLogicDropDownResponse = (function(_super) {
      __extends(SkipLogicDropDownResponse, _super);

      SkipLogicDropDownResponse.prototype.tagName = 'select';

      SkipLogicDropDownResponse.prototype.className = 'skiplogic__responseval';

      SkipLogicDropDownResponse.prototype.attach_to = function(target) {
        target.find('.skiplogic__responseval').remove();
        return SkipLogicDropDownResponse.__super__.attach_to.call(this, target);
      };

      SkipLogicDropDownResponse.prototype.bind_event = function(handler) {
        return SkipLogicDropDownResponse.__super__.bind_event.call(this, 'change', handler);
      };

      SkipLogicDropDownResponse.prototype.render = function() {
        var handle_model_cid_change,
          _this = this;

        SkipLogicDropDownResponse.__super__.render.apply(this, arguments);
        handle_model_cid_change = function() {
          return _this.val(_this.model.get('cid'));
        };
        this.model.off('change:cid', handle_model_cid_change);
        return this.model.on('change:cid', handle_model_cid_change);
      };

      function SkipLogicDropDownResponse(responses, model) {
        this.responses = responses;
        this.model = model;
        SkipLogicDropDownResponse.__super__.constructor.call(this, _.map(this.responses.models, function(response) {
          return {
            text: response.get('label'),
            value: response.cid
          };
        }));
      }

      return SkipLogicDropDownResponse;

    })($viewWidgets.DropDown);
    /*----------------------------------------------------------------------------------------------------------
    */

    /*----------------------------------------------------------------------------------------------------------
    */

    viewRowDetailSkipLogic.SkipLogicViewFactory = (function() {
      function SkipLogicViewFactory(survey) {
        this.survey = survey;
      }

      SkipLogicViewFactory.prototype.create_question_picker = function(target_question) {
        var model, set_options,
          _this = this;

        model = new $viewWidgets.DropDownModel();
        set_options = function() {
          var options;

          options = _.map(target_question.selectableRows(), function(row) {
            return {
              value: row.cid,
              text: row.getValue("label")
            };
          });
          options.unshift({
            value: -1,
            text: 'Select question from list'
          });
          return model.set('options', options);
        };
        set_options();
        this.survey.on('sortablestop', set_options);
        return new viewRowDetailSkipLogic.QuestionPicker(model);
      };

      SkipLogicViewFactory.prototype.create_operator_picker = function(question_type) {
        var operators;

        operators = question_type != null ? _.filter($skipLogicHelpers.operator_types, function(op_type) {
          var _ref4;

          return _ref4 = op_type.id, __indexOf.call(question_type.operators, _ref4) >= 0;
        }) : [];
        return new viewRowDetailSkipLogic.OperatorPicker(operators);
      };

      SkipLogicViewFactory.prototype.create_response_value_view = function(question, question_type, operator_type) {
        var type;

        if (question == null) {
          type = 'empty';
        } else if (operator_type.response_type != null) {
          type = operator_type.response_type;
        } else {
          type = question_type.response_type;
        }
        switch (type) {
          case 'empty':
            return new viewRowDetailSkipLogic.SkipLogicEmptyResponse();
          case 'text':
            return new viewRowDetailSkipLogic.SkipLogicTextResponse;
          case 'dropdown':
            return new viewRowDetailSkipLogic.SkipLogicDropDownResponse(question.getList().options);
          case 'integer':
          case 'decimal':
            return new viewRowDetailSkipLogic.SkipLogicTextResponse;
          default:
            return null;
        }
      };

      SkipLogicViewFactory.prototype.create_criterion_view = function(question_picker_view, operator_picker_view, response_value_view, presenter) {
        return new viewRowDetailSkipLogic.SkipLogicCriterion(question_picker_view, operator_picker_view, response_value_view, presenter);
      };

      SkipLogicViewFactory.prototype.create_criterion_builder_view = function() {
        return new viewRowDetailSkipLogic.SkipLogicCriterionBuilderView();
      };

      SkipLogicViewFactory.prototype.create_textarea = function(text, className) {
        return new $viewWidgets.TextArea(text, className);
      };

      SkipLogicViewFactory.prototype.create_button = function(text, className) {
        return new $viewWidgets.Button(text, className);
      };

      SkipLogicViewFactory.prototype.create_textbox = function(text, className, placeholder) {
        if (className == null) {
          className = '';
        }
        if (placeholder == null) {
          placeholder = '';
        }
        return new $viewWidgets.TextBox(text, className, placeholder);
      };

      SkipLogicViewFactory.prototype.create_label = function(text, className) {
        return new $viewWidgets.Label(text, className);
      };

      SkipLogicViewFactory.prototype.create_empty = function() {
        return new $viewWidgets.EmptyView();
      };

      return SkipLogicViewFactory;

    })();
    return viewRowDetailSkipLogic;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/mv.validationLogicHelpers', ['xlform/model.validationLogicParser', 'cs!xlform/mv.skipLogicHelpers'], function($validationLogicParser, $skipLogicHelpers) {
    var validationLogicHelpers, _ref, _ref1, _ref2;

    validationLogicHelpers = {};
    validationLogicHelpers.ValidationLogicHelperFactory = (function(_super) {
      __extends(ValidationLogicHelperFactory, _super);

      function ValidationLogicHelperFactory() {
        _ref = ValidationLogicHelperFactory.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      ValidationLogicHelperFactory.prototype.create_presenter = function(criterion_model, criterion_view) {
        return new validationLogicHelpers.ValidationLogicPresenter(criterion_model, criterion_view, this.current_question, this.survey, this.view_factory);
      };

      ValidationLogicHelperFactory.prototype.create_builder = function() {
        return new validationLogicHelpers.ValidationLogicBuilder(this.model_factory, this.view_factory, this.survey, this.current_question, this);
      };

      ValidationLogicHelperFactory.prototype.create_context = function() {
        return new validationLogicHelpers.ValidationLogicHelperContext(this.model_factory, this.view_factory, this, this.serialized_criteria);
      };

      return ValidationLogicHelperFactory;

    })($skipLogicHelpers.SkipLogicHelperFactory);
    validationLogicHelpers.ValidationLogicPresenter = (function(_super) {
      __extends(ValidationLogicPresenter, _super);

      function ValidationLogicPresenter() {
        _ref1 = ValidationLogicPresenter.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      ValidationLogicPresenter.prototype.change_question = function() {};

      return ValidationLogicPresenter;

    })($skipLogicHelpers.SkipLogicPresenter);
    validationLogicHelpers.ValidationLogicBuilder = (function(_super) {
      __extends(ValidationLogicBuilder, _super);

      function ValidationLogicBuilder() {
        _ref2 = ValidationLogicBuilder.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      ValidationLogicBuilder.prototype._parse_skip_logic_criteria = function(criteria) {
        return $validationLogicParser(criteria);
      };

      ValidationLogicBuilder.prototype._get_question = function() {
        return this.current_question;
      };

      ValidationLogicBuilder.prototype.build_empty_criterion = function() {
        var operator_picker_view, presenter, response_value_view;

        operator_picker_view = this.view_factory.create_operator_picker(this.current_question.get_type());
        response_value_view = this.view_factory.create_response_value_view(this.current_question, this.current_question.get_type(), this._operator_type());
        presenter = this.build_criterion_logic(this.model_factory.create_operator('empty'), operator_picker_view, response_value_view);
        presenter.model.change_question(this.current_question.cid);
        return presenter;
      };

      ValidationLogicBuilder.prototype.questions = function() {
        return [this.current_question];
      };

      ValidationLogicBuilder.prototype._operator_type = function() {
        var operator_type, operator_type_id;

        operator_type = ValidationLogicBuilder.__super__._operator_type.apply(this, arguments);
        if (operator_type == null) {
          operator_type_id = this.current_question.get_type().operators[0];
          operator_type = $skipLogicHelpers.operator_types[operator_type_id === 1 ? this.current_question.get_type().operators[1] : operator_type_id];
        }
        return operator_type;
      };

      return ValidationLogicBuilder;

    })($skipLogicHelpers.SkipLogicBuilder);
    validationLogicHelpers.ValidationLogicHelperContext = (function(_super) {
      __extends(ValidationLogicHelperContext, _super);

      ValidationLogicHelperContext.prototype.use_mode_selector_helper = function() {
        this.state = new validationLogicHelpers.ValidationLogicModeSelectorHelper(this.view_factory, this);
        return this.render(this.destination);
      };

      ValidationLogicHelperContext.prototype.use_hand_code_helper = function() {
        this.state = new validationLogicHelpers.ValidationLogicHandCodeHelper(this.state.serialize(), this.builder, this.view_factory, this);
        if (this.questionTypeHasNoValidationOperators()) {
          this.state.button = this.view_factory.create_empty();
        }
        this.render(this.destination);
      };

      function ValidationLogicHelperContext(model_factory, view_factory, helper_factory, serialized_criteria) {
        this.model_factory = model_factory;
        this.view_factory = view_factory;
        this.helper_factory = helper_factory;
        this.state = {
          serialize: function() {
            return serialized_criteria;
          }
        };
        if (this.questionTypeHasNoValidationOperators()) {
          this.use_hand_code_helper();
        } else {
          ValidationLogicHelperContext.__super__.constructor.apply(this, arguments);
        }
      }

      ValidationLogicHelperContext.prototype.questionTypeHasNoValidationOperators = function() {
        var operators, _ref3;

        operators = (_ref3 = $skipLogicHelpers.question_types[this.helper_factory.current_question.getValue('type').split(' ')[0]]) != null ? _ref3.operators : void 0;
        if (!operators) {
          operators = $skipLogicHelpers.question_types['default'].operators;
        }
        return operators.length === operators[0];
      };

      return ValidationLogicHelperContext;

    })($skipLogicHelpers.SkipLogicHelperContext);
    validationLogicHelpers.ValidationLogicModeSelectorHelper = (function(_super) {
      __extends(ValidationLogicModeSelectorHelper, _super);

      function ValidationLogicModeSelectorHelper(view_factory, context) {
        this.context = context;
        ValidationLogicModeSelectorHelper.__super__.constructor.apply(this, arguments);
        this.handcode_button = view_factory.create_button('<i>${}</i> Manually enter your validation logic in XLSForm code', 'skiplogic__button skiplogic__select-handcode');
      }

      return ValidationLogicModeSelectorHelper;

    })($skipLogicHelpers.SkipLogicModeSelectorHelper);
    validationLogicHelpers.ValidationLogicHandCodeHelper = (function(_super) {
      __extends(ValidationLogicHandCodeHelper, _super);

      ValidationLogicHandCodeHelper.prototype.render = function($destination) {
        var _this = this;

        $destination.replaceWith(this.$handCode);
        this.button.render().attach_to(this.$handCode);
        return this.button.bind_event('click', function() {
          _this.$handCode.replaceWith($destination);
          return _this.context.use_mode_selector_helper();
        });
      };

      ValidationLogicHandCodeHelper.prototype.serialize = function() {
        return this.textarea.val();
      };

      function ValidationLogicHandCodeHelper() {
        ValidationLogicHandCodeHelper.__super__.constructor.apply(this, arguments);
        this.$handCode = $("<div class=\"card__settings__fields__field\">\n  <label for=\"" + this.context.helper_factory.current_question.cid + "-handcode\">Validation Code:</label>\n  <span class=\"settings__input\">\n    <input type=\"text\" name=\"constraint\" id=\"" + this.context.helper_factory.current_question.cid + "-handcode\" class=\"text\" value=\"" + this.criteria + "\">\n  </span>\n</div>");
        this.textarea = this.$handCode.find('#' + this.context.helper_factory.current_question.cid + '-handcode');
      }

      return ValidationLogicHandCodeHelper;

    })($skipLogicHelpers.SkipLogicHandCodeHelper);
    return validationLogicHelpers;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/model.rowDetail.validationLogic', ['backbone', 'xlform/model.rowDetails.skipLogic'], function(Backbone, $skipLogicModel) {
    var rowDetailValidationLogic, _ref, _ref1, _ref2, _ref3, _ref4, _ref5, _ref6;

    rowDetailValidationLogic = {};
    rowDetailValidationLogic.ValidationLogicModelFactory = (function(_super) {
      __extends(ValidationLogicModelFactory, _super);

      function ValidationLogicModelFactory() {
        _ref = ValidationLogicModelFactory.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      ValidationLogicModelFactory.prototype.create_operator = function(type, symbol, id) {
        var operator;

        operator = null;
        switch (type) {
          case 'text':
            operator = new rowDetailValidationLogic.ValidationLogicTextOperator(symbol);
            break;
          case 'date':
            operator = new rowDetailValidationLogic.ValidationLogicDateOperator(symbol);
            break;
          case 'basic':
            operator = new rowDetailValidationLogic.ValidationLogicBasicOperator(symbol);
            break;
          case 'existence':
            operator = new rowDetailValidationLogic.ValidationLogicExistenceOperator(symbol);
            break;
          case 'select_multiple':
            operator = new rowDetailValidationLogic.ValidationLogicSelectMultipleOperator(symbol);
            break;
          case 'empty':
            return new $skipLogicModel.EmptyOperator();
        }
        operator.set('id', id);
        return operator;
      };

      ValidationLogicModelFactory.prototype.create_criterion_model = function() {
        return new rowDetailValidationLogic.ValidationLogicCriterion(this, this.survey);
      };

      return ValidationLogicModelFactory;

    })($skipLogicModel.SkipLogicFactory);
    rowDetailValidationLogic.ValidationLogicBasicOperator = (function(_super) {
      __extends(ValidationLogicBasicOperator, _super);

      function ValidationLogicBasicOperator() {
        _ref1 = ValidationLogicBasicOperator.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      ValidationLogicBasicOperator.prototype.serialize = function(question_name, response_value) {
        return '. ' + this.get('symbol') + ' ' + response_value;
      };

      return ValidationLogicBasicOperator;

    })($skipLogicModel.SkipLogicOperator);
    rowDetailValidationLogic.ValidationLogicTextOperator = (function(_super) {
      __extends(ValidationLogicTextOperator, _super);

      function ValidationLogicTextOperator() {
        _ref2 = ValidationLogicTextOperator.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      ValidationLogicTextOperator.prototype.serialize = function(question_name, response_value) {
        return ValidationLogicTextOperator.__super__.serialize.call(this, '', ' ' + "'" + response_value.replace(/'/g, "\\'") + "'");
      };

      return ValidationLogicTextOperator;

    })(rowDetailValidationLogic.ValidationLogicBasicOperator);
    rowDetailValidationLogic.ValidationLogicDateOperator = (function(_super) {
      __extends(ValidationLogicDateOperator, _super);

      function ValidationLogicDateOperator() {
        _ref3 = ValidationLogicDateOperator.__super__.constructor.apply(this, arguments);
        return _ref3;
      }

      ValidationLogicDateOperator.prototype.serialize = function(question_name, response_value) {
        if (response_value.indexOf('date') === -1) {
          response_value = "date('" + response_value + "')";
        }
        return ValidationLogicDateOperator.__super__.serialize.call(this, '', ' ' + response_value);
      };

      return ValidationLogicDateOperator;

    })(rowDetailValidationLogic.ValidationLogicBasicOperator);
    rowDetailValidationLogic.ValidationLogicExistenceOperator = (function(_super) {
      __extends(ValidationLogicExistenceOperator, _super);

      function ValidationLogicExistenceOperator() {
        _ref4 = ValidationLogicExistenceOperator.__super__.constructor.apply(this, arguments);
        return _ref4;
      }

      ValidationLogicExistenceOperator.prototype.serialize = function() {
        return ValidationLogicExistenceOperator.__super__.serialize.call(this, '', "''");
      };

      return ValidationLogicExistenceOperator;

    })(rowDetailValidationLogic.ValidationLogicBasicOperator);
    rowDetailValidationLogic.ValidationLogicSelectMultipleOperator = (function(_super) {
      __extends(ValidationLogicSelectMultipleOperator, _super);

      function ValidationLogicSelectMultipleOperator() {
        _ref5 = ValidationLogicSelectMultipleOperator.__super__.constructor.apply(this, arguments);
        return _ref5;
      }

      ValidationLogicSelectMultipleOperator.prototype.serialize = function(question_name, response_value) {
        var selected;

        selected = "selected(., '" + response_value + "')";
        if (this.get('is_negated')) {
          return 'not(' + selected + ')';
        }
        return selected;
      };

      return ValidationLogicSelectMultipleOperator;

    })($skipLogicModel.SelectMultipleSkipLogicOperator);
    rowDetailValidationLogic.ValidationLogicCriterion = (function(_super) {
      __extends(ValidationLogicCriterion, _super);

      function ValidationLogicCriterion() {
        _ref6 = ValidationLogicCriterion.__super__.constructor.apply(this, arguments);
        return _ref6;
      }

      ValidationLogicCriterion.prototype.change_question = function(cid) {
        var old_question_type, question_type, _ref7, _ref8;

        old_question_type = this._get_question() ? this._get_question().get_type() : {
          name: null
        };
        this.set("question_cid", cid);
        question_type = this._get_question().get_type();
        if ((this.get("operator").get_id() != null) && !(_ref7 = this.get("operator").get_id(), __indexOf.call(question_type.operators, _ref7) >= 0)) {
          this.change_operator(question_type.operators[0] !== 1 ? question_type.operators[0] : question_type.operators[1]);
        } else if (old_question_type.name !== question_type.name) {
          this.change_operator(this.get("operator").get_value());
        }
        if ((this.get("operator").get_type().response_type === null) && this._get_question().response_type !== ((_ref8 = this.get("response_value")) != null ? _ref8.get_type() : void 0)) {
          return this.change_response(this.get("response_value").get("value"));
        }
      };

      return ValidationLogicCriterion;

    })($skipLogicModel.SkipLogicCriterion);
    return rowDetailValidationLogic;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/view.rowDetail.ValidationLogic', ['cs!xlform/view.rowDetail.SkipLogic', 'cs!xlform/view.widgets', 'cs!xlform/mv.skipLogicHelpers'], function($skipLogicView, $viewWidgets, $skipLogicHelpers) {
    var viewRowDetailValidationLogic, _ref, _ref1;

    viewRowDetailValidationLogic = {};
    viewRowDetailValidationLogic.ValidationLogicViewFactory = (function(_super) {
      __extends(ValidationLogicViewFactory, _super);

      function ValidationLogicViewFactory() {
        _ref = ValidationLogicViewFactory.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      ValidationLogicViewFactory.prototype.create_criterion_builder_view = function() {
        return new viewRowDetailValidationLogic.ValidationLogicCriterionBuilder();
      };

      ValidationLogicViewFactory.prototype.create_question_picker = function() {
        return new viewRowDetailValidationLogic.ValidationLogicQuestionPicker;
      };

      ValidationLogicViewFactory.prototype.create_operator_picker = function(question_type) {
        var operators;

        operators = _.filter($skipLogicHelpers.operator_types, function(op_type) {
          var _ref1;

          return op_type.id !== 1 && (_ref1 = op_type.id, __indexOf.call(question_type.operators, _ref1) >= 0);
        });
        return new $skipLogicView.OperatorPicker(operators);
      };

      return ValidationLogicViewFactory;

    })($skipLogicView.SkipLogicViewFactory);
    viewRowDetailValidationLogic.ValidationLogicCriterionBuilder = (function(_super) {
      __extends(ValidationLogicCriterionBuilder, _super);

      function ValidationLogicCriterionBuilder() {
        _ref1 = ValidationLogicCriterionBuilder.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      ValidationLogicCriterionBuilder.prototype.render = function() {
        ValidationLogicCriterionBuilder.__super__.render.apply(this, arguments);
        this.$el.html(this.$el.html().replace('only be displayed', 'be valid only'));
        return this;
      };

      return ValidationLogicCriterionBuilder;

    })($skipLogicView.SkipLogicCriterionBuilderView);
    viewRowDetailValidationLogic.ValidationLogicQuestionPicker = (function(_super) {
      __extends(ValidationLogicQuestionPicker, _super);

      function ValidationLogicQuestionPicker() {
        ValidationLogicQuestionPicker.__super__.constructor.call(this, "This question's response has to be");
      }

      ValidationLogicQuestionPicker.prototype.attach_to = function(target) {
        target.find('.skiplogic__rowselect').remove();
        return ValidationLogicQuestionPicker.__super__.attach_to.call(this, target);
      };

      return ValidationLogicQuestionPicker;

    })($viewWidgets.Label);
    return viewRowDetailValidationLogic;
  });

}).call(this);


(function() {
  define('cs!xlform/model.rowDetailMixins', ['cs!xlform/mv.skipLogicHelpers', 'xlform/model.rowDetails.skipLogic', 'cs!xlform/view.rowDetail.SkipLogic', 'cs!xlform/model.utils', 'cs!xlform/mv.validationLogicHelpers', 'cs!xlform/model.rowDetail.validationLogic', 'cs!xlform/view.rowDetail.ValidationLogic'], function($skipLogicHelpers, $modelRowDetailsSkipLogic, $viewRowDetailSkipLogic, $modelUtils, $validationLogicHelpers, $modelRowDetailValidationLogic, $viewRowDetailValidationLogic) {
    var SkipLogicDetailMixin, ValidationLogicMixin, rowDetailMixins;

    SkipLogicDetailMixin = {
      getValue: function() {
        var v;

        v = this.serialize();
        if (v === "undefined") {
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.error("Serialized value is returning a string, undefined");
          }
          v = "";
        }
        return v;
      },
      postInitialize: function() {
        var helper_factory, model_factory, survey, view_factory;

        survey = this.getSurvey();
        model_factory = new $modelRowDetailsSkipLogic.SkipLogicFactory(survey);
        view_factory = new $viewRowDetailSkipLogic.SkipLogicViewFactory(survey);
        helper_factory = new $skipLogicHelpers.SkipLogicHelperFactory(model_factory, view_factory, survey, this._parent, this.get('value'));
        return this.facade = new $skipLogicHelpers.SkipLogicPresentationFacade(model_factory, helper_factory, view_factory);
      },
      serialize: function() {
        return this.facade.serialize();
      },
      parse: function() {},
      linkUp: function(ctx) {
        return this.facade.initialize();
      }
    };
    ValidationLogicMixin = {
      getValue: function() {
        var v;

        v = this.serialize();
        if (v === "undefined") {
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.error("Serialized value is returning a string, undefined");
          }
          v = "";
        }
        return v;
      },
      postInitialize: function() {
        var helper_factory, model_factory, survey, view_factory;

        survey = this.getSurvey();
        model_factory = new $modelRowDetailValidationLogic.ValidationLogicModelFactory(survey);
        view_factory = new $viewRowDetailValidationLogic.ValidationLogicViewFactory(survey);
        helper_factory = new $validationLogicHelpers.ValidationLogicHelperFactory(model_factory, view_factory, survey, this._parent, this.get('value'));
        return this.facade = new $skipLogicHelpers.SkipLogicPresentationFacade(model_factory, helper_factory, view_factory);
      },
      serialize: function() {
        return this.facade.serialize();
      },
      parse: function() {},
      linkUp: function(ctx) {
        return this.facade.initialize();
      }
    };
    rowDetailMixins = {
      relevant: SkipLogicDetailMixin,
      constraint: ValidationLogicMixin,
      label: {
        postInitialize: function() {}
      },
      name: {
        deduplicate: function(survey) {
          var names,
            _this = this;

          names = [];
          survey.forEachRow(function(r) {
            var name;

            if (r.get('name') !== _this) {
              name = r.getValue("name");
              return names.push(name);
            }
          }, {
            includeGroups: true
          });
          return $modelUtils.sluggifyLabel(this.get('value'), names);
        }
      }
    };
    return rowDetailMixins;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  define('cs!xlform/model.base', ['underscore', 'backbone', 'backbone-validation', 'cs!xlform/view.utils', 'cs!xlform/model.configs', 'cs!xlform/model.rowDetailMixins'], function(_, Backbone, validation, $viewUtils, $configs, $rowDetailMixins) {
    var base;

    _.extend(validation.validators, {
      invalidChars: function(value, attr, customValue) {
        if (!$viewUtils.Validator.__validators.invalidChars(value, customValue)) {
          return "" + value + " contains invalid characters";
        }
      },
      unique: function(value, attr, customValue, model) {
        var rows, values;

        rows = model.getSurvey().rows.pluck(model.key);
        values = _.map(rows, function(rd) {
          return rd.get('value');
        });
        if (!$viewUtils.Validator.__validators.unique(value, values)) {
          return "Question name isn't unique";
        } else {
          return ;
        }
      }
    });
    _.extend(Backbone.Model.prototype, validation.mixin);
    base = {};
    base.BaseCollection = (function(_super) {
      __extends(BaseCollection, _super);

      function BaseCollection(arg, opts) {
        if (arg && "_parent" in arg) {
          throw new Error("_parent chould be assigned as property to 2nd argument to XLF.BaseCollection (not first)");
        }
        if (opts && opts._parent) {
          this._parent = opts._parent;
        }
        BaseCollection.__super__.constructor.call(this, arg, opts);
      }

      BaseCollection.prototype.getSurvey = function() {
        var parent;

        parent = this._parent;
        while (parent._parent) {
          parent = parent._parent;
        }
        return parent;
      };

      return BaseCollection;

    })(Backbone.Collection);
    base.BaseModel = (function(_super) {
      __extends(BaseModel, _super);

      function BaseModel(arg, opts) {
        if (opts && "_parent" in opts) {
          this._parent = opts._parent;
        } else if ("object" === typeof arg && "_parent" in arg) {
          this._parent = arg._parent;
          delete arg._parent;
        }
        BaseModel.__super__.constructor.call(this, arg, opts);
      }

      BaseModel.prototype.parse = function() {};

      BaseModel.prototype.linkUp = function(ctx) {};

      BaseModel.prototype.finalize = function() {};

      BaseModel.prototype.getValue = function(what) {
        var resp;

        if (what) {
          resp = this.get(what);
          if (resp === void 0) {
            throw new Error("Could not get value");
          }
          if (resp.getValue) {
            resp = resp.getValue();
          }
        } else {
          resp = this.get("value");
        }
        return resp;
      };

      BaseModel.prototype.setDetail = function(what, value) {
        if (value.constructor === base.RowDetail) {
          return this.set(what, value);
        } else {
          return this.set(what, new base.RowDetail({
            key: what,
            value: value
          }, {
            _parent: this
          }));
        }
      };

      BaseModel.prototype.parentRow = function() {
        return this._parent._parent;
      };

      BaseModel.prototype.precedingRow = function() {
        var ii;

        ii = this._parent.models.indexOf(this);
        return this._parent.at(ii - 1);
      };

      BaseModel.prototype.nextRow = function() {
        var ii;

        ii = this._parent.models.indexOf(this);
        return this._parent.at(ii + 1);
      };

      BaseModel.prototype.getSurvey = function() {
        var parent;

        parent = this._parent;
        if (parent === null) {
          return null;
        }
        while (parent._parent) {
          parent = parent._parent;
        }
        return parent;
      };

      return BaseModel;

    })(Backbone.Model);
    base.RowDetail = (function(_super) {
      __extends(RowDetail, _super);

      RowDetail.prototype.idAttribute = "name";

      RowDetail.prototype.validation = function() {
        if (this.key === 'name') {
          return {
            value: {
              unique: true,
              required: true
            }
          };
        } else if (this.key === 'calculation') {
          return {
            value: {
              required: true
            }
          };
        } else if (this.key === 'label' && this._parent.constructor.key !== 'group') {
          return {
            value: {
              required: true
            }
          };
        }
        return {};
      };

      function RowDetail(_arg, opts) {
        var vals2set, value;

        this.key = _arg.key, value = _arg.value;
        this.validation = __bind(this.validation, this);
        this._parent = opts._parent;
        if (this.key in $rowDetailMixins) {
          _.extend(this, $rowDetailMixins[this.key]);
        }
        RowDetail.__super__.constructor.call(this);
        if (value !== (void 0) && value !== false && value !== null) {
          vals2set = {};
          if (_.isString(value) || _.isNumber(value)) {
            vals2set.value = value;
          } else if (_.isObject(value) && "value" in value) {
            _.extend(vals2set, value);
          } else {
            vals2set.value = value;
          }
          this.set(vals2set);
        }
        this._order = $configs.columnOrder(this.key);
        this.postInitialize();
      }

      RowDetail.prototype.postInitialize = function() {};

      RowDetail.prototype.initialize = function() {
        var _this = this;

        if (this.get("_hideUnlessChanged")) {
          this.hidden = true;
          this._oValue = this.get("value");
          this.on("change", function() {
            return this.hidden = this.get("value") === this._oValue;
          });
        }
        this.on("change:value", function(rd, val, ctxt) {
          _this._parent.trigger("change", _this.key, val, ctxt);
          _this._parent.trigger("detail-change", _this.key, val, ctxt);
          return _this.getSurvey().trigger("row-detail-change", _this._parent, _this.key, val, ctxt);
        });
        if (this.key === "type") {
          return this.on("change:list", function(rd, val, ctxt) {
            return _this._parent.trigger("change", _this.key, val, ctxt);
          });
        }
      };

      return RowDetail;

    })(base.BaseModel);
    return base;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/model.choices', ['cs!xlform/model.base', 'cs!xlform/model.utils'], function(base, $modelUtils) {
    var choices, _ref, _ref1, _ref2;

    choices = {};
    choices.Option = (function(_super) {
      __extends(Option, _super);

      function Option() {
        _ref = Option.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Option.prototype.initialize = function() {
        return this.unset("list name");
      };

      Option.prototype.destroy = function() {
        var choicelist, choicelist_cid, survey;

        choicelist = this.list()._parent;
        choicelist_cid = choicelist.cid;
        survey = choicelist.collection._parent;
        this.collection.remove(this);
        return survey.trigger('remove-option', choicelist_cid, this.cid);
      };

      Option.prototype.list = function() {
        return this.collection;
      };

      Option.prototype.toJSON = function() {
        var attribute, attributes, key, _ref1;

        attributes = {};
        _ref1 = this.attributes;
        for (key in _ref1) {
          attribute = _ref1[key];
          attributes[key] = this.get(key);
        }
        return attributes;
      };

      return Option;

    })(base.BaseModel);
    choices.Options = (function(_super) {
      __extends(Options, _super);

      function Options() {
        _ref1 = Options.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      Options.prototype.model = choices.Option;

      return Options;

    })(base.BaseCollection);
    choices.ChoiceList = (function(_super) {
      __extends(ChoiceList, _super);

      ChoiceList.prototype.idAttribute = "name";

      function ChoiceList(opts, context) {
        var options;

        if (opts == null) {
          opts = {};
        }
        options = opts.options || [];
        ChoiceList.__super__.constructor.call(this, {
          name: opts.name
        }, context);
        this.options = new choices.Options(options || [], {
          _parent: this
        });
      }

      ChoiceList.prototype.summaryObj = function() {
        return this.toJSON();
      };

      ChoiceList.prototype.finalize = function() {
        var label, name, names, option, _i, _len, _ref2;

        names = [];
        _ref2 = this.options.models;
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          option = _ref2[_i];
          label = option.get("label");
          name = option.get("name");
          if (!name) {
            name = $modelUtils.sluggify(label, {
              preventDuplicates: names,
              lowerCase: true,
              lrstrip: true,
              characterLimit: 14,
              incrementorPadding: false,
              validXmlTag: false
            });
            option.set("name", name);
          }
          names.push(name);
        }
      };

      ChoiceList.prototype.clone = function() {
        var json;

        json = this.toJSON();
        delete json.name;
        return new choices.ChoiceList(json);
      };

      ChoiceList.prototype.toJSON = function() {
        this.finalize();
        return {
          name: this.get("name"),
          options: this.options.invoke("toJSON")
        };
      };

      ChoiceList.prototype.getNames = function() {
        var names;

        names = this.options.map(function(opt) {
          return opt.get("name");
        });
        return _.compact(names);
      };

      return ChoiceList;

    })(base.BaseModel);
    choices.ChoiceLists = (function(_super) {
      __extends(ChoiceLists, _super);

      function ChoiceLists() {
        _ref2 = ChoiceLists.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      ChoiceLists.prototype.model = choices.ChoiceList;

      ChoiceLists.prototype.create = function() {
        var cl;

        this.add(cl = new choices.ChoiceList({
          name: $modelUtils.txtid()
        }));
        return cl;
      };

      ChoiceLists.prototype.summaryObj = function(shorter) {
        var model, out, _i, _len, _ref3;

        if (shorter == null) {
          shorter = false;
        }
        out = {};
        _ref3 = this.models;
        for (_i = 0, _len = _ref3.length; _i < _len; _i++) {
          model = _ref3[_i];
          if (shorter) {
            out[model.get("name")] = model.summaryObj().options;
          } else {
            out[model.get("name")] = model.summaryObj();
          }
        }
        return out;
      };

      return ChoiceLists;

    })(base.BaseCollection);
    return choices;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/model.surveyDetail', ['cs!xlform/model.base'], function(base) {
    var SurveyDetail, SurveyDetails, _ref, _ref1;

    SurveyDetail = (function(_super) {
      __extends(SurveyDetail, _super);

      function SurveyDetail() {
        _ref = SurveyDetail.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      SurveyDetail.prototype.idAttribute = "name";

      SurveyDetail.prototype.toJSON = function() {
        var nameSlashType;

        if (this.get("value")) {
          nameSlashType = this.get("name");
          return {
            name: nameSlashType,
            type: nameSlashType
          };
        } else {
          return false;
        }
      };

      return SurveyDetail;

    })(base.BaseModel);
    SurveyDetails = (function(_super) {
      __extends(SurveyDetails, _super);

      function SurveyDetails() {
        _ref1 = SurveyDetails.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      SurveyDetails.prototype.model = SurveyDetail;

      SurveyDetails.prototype.loadSchema = function(schema) {
        var item, _i, _len, _ref2;

        if (!(schema instanceof Backbone.Collection)) {
          throw new Error("Schema must be a Backbone.Collection");
        }
        _ref2 = schema.models;
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          item = _ref2[_i];
          this.add(new SurveyDetail(item._forSurvey()));
        }
        this._schema = schema;
        this.add = this.loadSchema = function() {
          throw new Error("New survey details must be added to the schema");
        };
        return this;
      };

      SurveyDetails.prototype.importDefaults = function() {
        var item, relevantDetail, _i, _len, _ref2;

        _ref2 = this._schema.models;
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          item = _ref2[_i];
          relevantDetail = this.get(item.get("name"));
          relevantDetail.set("value", item.get("default"));
        }
        return ;
      };

      SurveyDetails.prototype.importDetail = function(detail) {
        var dtobj;

        if ((dtobj = this.get(detail.type))) {
          return dtobj.set("value", true);
        } else {
          throw new Error("SurveyDetail `" + key + "` not loaded from schema. [Aliases have not been implemented]");
        }
      };

      return SurveyDetails;

    })(base.BaseCollection);
    return {
      SurveyDetails: SurveyDetails,
      SurveyDetail: SurveyDetail
    };
  });

}).call(this);


(function() {
  var __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/model.aliases', ['underscore'], function(_) {
    var aliases, aliases_dict, q;

    aliases_dict = {
      group: ["group", "begin group", "end group", "begin_group", "end_group"],
      repeat: ["repeat", "begin repeat", "end repeat", "begin_repeat", "end_repeat"],
      score: ["begin score", "end score"],
      rank: ["begin rank", "end rank"]
    };
    aliases = function(name) {
      return aliases_dict[name] || [name];
    };
    q = {};
    q.groupable = function() {
      return _.flatten([aliases('group'), aliases('repeat'), aliases('score'), aliases('rank')]);
    };
    q.groupsOrRepeats = function() {
      return _.flatten([aliases('group'), aliases('repeat')]);
    };
    q.requiredSheetNameList = function() {
      return ['survey'];
    };
    q.testGroupable = function(type) {
      var out;

      out = false;
      if (__indexOf.call(aliases_dict.group, type) >= 0) {
        out = {
          type: 'group'
        };
      } else if (__indexOf.call(aliases_dict.repeat, type) >= 0) {
        out = {
          type: 'repeat'
        };
      } else if (__indexOf.call(aliases_dict.score, type) >= 0) {
        out = {
          type: 'score'
        };
      } else if (__indexOf.call(aliases_dict.rank, type) >= 0) {
        out = {
          type: 'rank'
        };
      }
      if (out && out.type) {
        out.begin = !type.match(/end/);
      }
      return out;
    };
    q.testGroupOrRepeat = function(type) {
      console.error("q.testGroupOrRepeat is renamed to q.testGroupable");
      return q.testGroupable(type);
    };
    q.hiddenTypes = function() {
      return _.flatten([['imei', 'deviceid'], ['start'], ['end'], ['today'], ['simserial'], ['subscriberid'], ['phonenumber']]);
    };
    aliases.custom = q;
    aliases.q = aliases.custom;
    return aliases;
  });

}).call(this);


(function() {
  define('cs!xlform/model.rowDetail', ['cs!xlform/model.base'], function($base) {
    return {
      RowDetail: $base.RowDetail
    };
  });

}).call(this);


(function() {
  var global,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; },
    __slice = [].slice;

  global = typeof window !== "undefined" && window !== null ? window : process;

  define('cs!xlform/model.row', ['underscore', 'backbone', 'cs!xlform/model.base', 'cs!xlform/model.configs', 'cs!xlform/model.utils', 'cs!xlform/model.surveyDetail', 'cs!xlform/model.aliases', 'cs!xlform/model.rowDetail', 'cs!xlform/model.choices', 'cs!xlform/mv.skipLogicHelpers'], function(_, Backbone, base, $configs, $utils, $surveyDetail, $aliases, $rowDetail, $choices, $skipLogicHelpers) {
    var RankMixin, RankRow, RankRows, ScoreChoiceList, ScoreMixin, ScoreRankMixin, ScoreRow, ScoreRows, SimpleRow, row, _ref, _ref1, _ref2, _ref3, _ref4, _ref5, _ref6;

    row = {};
    row.BaseRow = (function(_super) {
      __extends(BaseRow, _super);

      BaseRow.kls = "BaseRow";

      function BaseRow(attributes, options) {
        var key, val;

        if (attributes == null) {
          attributes = {};
        }
        if (options == null) {
          options = {};
        }
        for (key in attributes) {
          val = attributes[key];
          if (key === "") {
            delete attributes[key];
          }
        }
        BaseRow.__super__.constructor.call(this, attributes, options);
      }

      BaseRow.prototype.initialize = function() {
        return this.convertAttributesToRowDetails();
      };

      BaseRow.prototype.isError = function() {
        return false;
      };

      BaseRow.prototype.convertAttributesToRowDetails = function() {
        var key, val, _ref, _results;

        _ref = this.attributes;
        _results = [];
        for (key in _ref) {
          val = _ref[key];
          if (!(val instanceof $rowDetail.RowDetail)) {
            _results.push(this.set(key, new $rowDetail.RowDetail({
              key: key,
              value: val
            }, {
              _parent: this
            }), {
              silent: true
            }));
          } else {
            _results.push(void 0);
          }
        }
        return _results;
      };

      BaseRow.prototype.attributesArray = function() {
        var arr, k, v;

        arr = (function() {
          var _ref, _results;

          _ref = this.attributes;
          _results = [];
          for (k in _ref) {
            v = _ref[k];
            _results.push([k, v]);
          }
          return _results;
        }).call(this);
        arr.sort(function(a, b) {
          if (a[1]._order < b[1]._order) {
            return -1;
          } else {
            return 1;
          }
        });
        return arr;
      };

      BaseRow.prototype.isInGroup = function() {
        var _ref, _ref1;

        return ((_ref = this._parent) != null ? (_ref1 = _ref._parent) != null ? _ref1.constructor.kls : void 0 : void 0) === "Group";
      };

      BaseRow.prototype.detach = function(opts) {
        if (this._parent) {
          this._parent.remove(this, opts);
          this._parent = null;
        }
        return  ;
      };

      BaseRow.prototype.selectableRows = function() {
        var limit, non_selectable, questions, survey,
          _this = this;

        questions = [];
        limit = false;
        non_selectable = ['datetime', 'time', 'note', 'calculate', 'group'];
        survey = this.getSurvey();
        if (survey === null) {
          return null;
        }
        survey.forEachRow(function(question) {
          var _ref;

          limit = limit || question === _this;
          if (!limit && (_ref = question.getValue('type'), __indexOf.call(non_selectable, _ref) < 0)) {
            return questions.push(question);
          }
        }, {
          includeGroups: true
        });
        return questions;
      };

      BaseRow.prototype.export_relevant_values = function(survey_arr, additionalSheets) {
        return survey_arr.push(this.toJSON2());
      };

      BaseRow.prototype.toJSON2 = function() {
        var key, outObj, result, val, _i, _len, _ref, _ref1, _ref2;

        outObj = {};
        _ref = this.attributesArray();
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          _ref1 = _ref[_i], key = _ref1[0], val = _ref1[1];
          if (key === 'type' && ((_ref2 = val.get('typeId')) === 'select_one' || _ref2 === 'select_multiple')) {
            result = {};
            result[val.get('typeId')] = val.get('listName');
          } else {
            result = this.getValue(key);
          }
          if (!this.hidden) {
            if (_.isBoolean(result)) {
              outObj[key] = $configs.boolOutputs[result ? "true" : "false"];
            } else if ('' !== result) {
              outObj[key] = result;
            }
          }
        }
        return outObj;
      };

      BaseRow.prototype.toJSON = function() {
        var key, outObj, result, val, _i, _len, _ref, _ref1;

        outObj = {};
        _ref = this.attributesArray();
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          _ref1 = _ref[_i], key = _ref1[0], val = _ref1[1];
          result = this.getValue(key);
          if (!this.hidden) {
            if (_.isBoolean(result)) {
              outObj[key] = $configs.boolOutputs[result ? "true" : "false"];
            } else {
              outObj[key] = result;
            }
          }
        }
        return outObj;
      };

      return BaseRow;

    })(base.BaseModel);
    SimpleRow = (function(_super) {
      __extends(SimpleRow, _super);

      function SimpleRow() {
        _ref = SimpleRow.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      SimpleRow.prototype.finalize = function() {
        return ;
      };

      SimpleRow.prototype.getTypeId = function() {
        return this.get('type');
      };

      SimpleRow.prototype.linkUp = function() {};

      SimpleRow.prototype._isSelectQuestion = function() {
        return false;
      };

      SimpleRow.prototype.get_type = function() {
        return $skipLogicHelpers.question_types[this.getTypeId()] || $skipLogicHelpers.question_types['default'];
      };

      SimpleRow.prototype.getValue = function(which) {
        return this.get(which);
      };

      return SimpleRow;

    })(Backbone.Model);
    RankRow = (function(_super) {
      __extends(RankRow, _super);

      function RankRow() {
        _ref1 = RankRow.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      RankRow.prototype.initialize = function() {
        return this.set('type', 'rank__level');
      };

      RankRow.prototype.export_relevant_values = function(surv, sheets) {
        return surv.push(this.attributes);
      };

      return RankRow;

    })(SimpleRow);
    ScoreRankMixin = (function() {
      function ScoreRankMixin() {}

      ScoreRankMixin.prototype._extendAll = function(rr) {
        var extend_to_row, subrow, _i, _len, _ref2, _toJSON,
          _this = this;

        extend_to_row = function(val, key) {
          if (_.isFunction(val)) {
            return rr[key] = function() {
              var args;

              args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
              return val.apply(rr, args);
            };
          } else {
            return rr[key] = val;
          }
        };
        _.each(this, extend_to_row);
        extend_to_row(this.forEachRow, 'forEachRow');
        rr._afterIterator = function(cb, ctxt) {
          var obj;

          obj = {
            export_relevant_values: function(surv, addl) {
              return surv.push({
                type: "end " + (rr._beginEndKey())
              });
            },
            toJSON: function() {
              return {
                type: "end " + (rr._beginEndKey())
              };
            }
          };
          if (ctxt.includeGroupEnds) {
            return cb(obj);
          }
        };
        _toJSON = rr.toJSON;
        rr.clone = function() {
          var attributes, item, options, r2, rankRow, scoreRow, _i, _j, _k, _l, _len, _len1, _len2, _len3, _ref2, _ref3, _ref4, _ref5;

          attributes = rr.toJSON2();
          options = {
            _parent: rr._parent,
            add: false,
            merge: false,
            remove: false,
            silent: true
          };
          r2 = new row.Row(attributes, options);
          r2._isCloned = true;
          if (rr._rankRows) {
            _ref2 = rr._rankRows.models;
            for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
              rankRow = _ref2[_i];
              r2._rankRows.add(rankRow.toJSON());
            }
            r2._rankLevels = rr.getSurvey().choices.add({
              name: $utils.txtid()
            });
            _ref3 = rr.getList().options.models;
            for (_j = 0, _len1 = _ref3.length; _j < _len1; _j++) {
              item = _ref3[_j];
              r2._rankLevels.options.add(item.toJSON());
            }
            r2.set('kobo--rank-items', r2._rankLevels.get('name'));
            this.convertAttributesToRowDetails();
            r2.get('type').set('list', r2._rankLevels);
          } else {
            _ref4 = rr._scoreRows.models;
            for (_k = 0, _len2 = _ref4.length; _k < _len2; _k++) {
              scoreRow = _ref4[_k];
              r2._scoreRows.add(scoreRow.toJSON());
            }
            r2._scoreChoices = rr.getSurvey().choices.add({
              name: $utils.txtid()
            });
            _ref5 = rr.getList().options.models;
            for (_l = 0, _len3 = _ref5.length; _l < _len3; _l++) {
              item = _ref5[_l];
              r2._scoreChoices.options.add(item.toJSON());
            }
            r2.set('kobo--score-choices', r2._scoreChoices.get('name'));
            this.convertAttributesToRowDetails();
            r2.get('type').set('list', r2._scoreChoices);
          }
          return r2;
        };
        rr.toJSON = function() {
          var out;

          out = _toJSON.call(rr);
          out.type = "begin " + (rr._beginEndKey());
          if (typeof this._additionalJson === 'function') {
            _.extend(out, this._additionalJson());
          }
          return out;
        };
        _.each(this.constructor.prototype, extend_to_row);
        if (rr.attributes.__rows) {
          _ref2 = rr.attributes.__rows;
          for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
            subrow = _ref2[_i];
            this[this._rowAttributeName].add(subrow);
          }
          return delete rr.attributes.__rows;
        }
      };

      ScoreRankMixin.prototype.getValue = function(which) {
        return this.get(which);
      };

      ScoreRankMixin.prototype.forEachRow = function(cb, ctx) {
        cb(this);
        this[this._rowAttributeName].each(function(subrow) {
          return cb(subrow);
        });
        if ('_afterIterator' in this) {
          return this._afterIterator(cb, ctx);
        }
      };

      return ScoreRankMixin;

    })();
    RankRows = (function(_super) {
      __extends(RankRows, _super);

      function RankRows() {
        _ref2 = RankRows.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      RankRows.prototype.model = RankRow;

      return RankRows;

    })(Backbone.Collection);
    RankMixin = (function(_super) {
      __extends(RankMixin, _super);

      function RankMixin(rr) {
        var rankConstraintMessageKey;

        this._rankRows = new RankRows();
        this._rowAttributeName = '_rankRows';
        this._extendAll(rr);
        rankConstraintMessageKey = 'kobo--rank-constraint-message';
        if (!rr.get(rankConstraintMessageKey)) {
          rr.set(rankConstraintMessageKey, 'Items cannot be selected more than once');
        }
      }

      RankMixin.prototype._beginEndKey = function() {
        return 'rank';
      };

      RankMixin.prototype.linkUp = function(ctx) {
        var rank_list_id, _ref3,
          _this = this;

        rank_list_id = (_ref3 = this.get('kobo--rank-items')) != null ? _ref3.get('value') : void 0;
        if (rank_list_id) {
          this._rankLevels = this.getSurvey().choices.get(rank_list_id);
        } else {
          this._rankLevels = this.getSurvey().choices.create();
        }
        this._additionalJson = function() {
          return {
            'kobo--rank-items': _this.getList().get('name')
          };
        };
        return this.getList = function() {
          return _this._rankLevels;
        };
      };

      RankMixin.prototype.export_relevant_values = function(survey_arr, additionalSheets) {
        var begin_xlsformrow;

        if (this._rankLevels) {
          additionalSheets['choices'].add(this._rankLevels);
        }
        begin_xlsformrow = _.clone(this.toJSON2());
        begin_xlsformrow.type = "begin rank";
        survey_arr.push(begin_xlsformrow);
        return ;
      };

      return RankMixin;

    })(ScoreRankMixin);
    ScoreChoiceList = (function(_super) {
      __extends(ScoreChoiceList, _super);

      function ScoreChoiceList() {
        _ref3 = ScoreChoiceList.__super__.constructor.apply(this, arguments);
        return _ref3;
      }

      return ScoreChoiceList;

    })(Array);
    ScoreRow = (function(_super) {
      __extends(ScoreRow, _super);

      function ScoreRow() {
        _ref4 = ScoreRow.__super__.constructor.apply(this, arguments);
        return _ref4;
      }

      ScoreRow.prototype.initialize = function() {
        return this.set('type', 'score__row');
      };

      ScoreRow.prototype.export_relevant_values = function(surv, sheets) {
        return surv.push(this.attributes);
      };

      return ScoreRow;

    })(SimpleRow);
    ScoreRows = (function(_super) {
      __extends(ScoreRows, _super);

      function ScoreRows() {
        _ref5 = ScoreRows.__super__.constructor.apply(this, arguments);
        return _ref5;
      }

      ScoreRows.prototype.model = ScoreRow;

      return ScoreRows;

    })(Backbone.Collection);
    ScoreMixin = (function(_super) {
      __extends(ScoreMixin, _super);

      function ScoreMixin(rr) {
        this._scoreRows = new ScoreRows();
        this._rowAttributeName = '_scoreRows';
        this._extendAll(rr);
      }

      ScoreMixin.prototype._beginEndKey = function() {
        return 'score';
      };

      ScoreMixin.prototype.linkUp = function(ctx) {
        var score_list_id, score_list_id_item,
          _this = this;

        this.getList = function() {
          return _this._scoreChoices;
        };
        this._additionalJson = function() {
          return {
            'kobo--score-choices': _this.getList().get('name')
          };
        };
        score_list_id_item = this.get('kobo--score-choices');
        if (score_list_id_item) {
          score_list_id = score_list_id_item.get('value');
          if (score_list_id) {
            this._scoreChoices = this.getSurvey().choices.get(score_list_id);
          } else {
            ctx.warnings.push("Score choices list not found");
            this._scoreChoices = this.getSurvey().choices.add({});
          }
        } else {
          ctx.warnings.push("Score choices list not set");
          this._scoreChoices = this.getSurvey().choices.add({
            name: $utils.txtid()
          });
        }
        return ;
      };

      ScoreMixin.prototype.export_relevant_values = function(survey_arr, additionalSheets) {
        var output, score_list;

        score_list = this._scoreChoices;
        if (score_list) {
          additionalSheets['choices'].add(score_list);
        }
        output = _.clone(this.toJSON2());
        output.type = "begin score";
        output['kobo--score-choices'] = this.getList().get('name');
        survey_arr.push(output);
        return ;
      };

      return ScoreMixin;

    })(ScoreRankMixin);
    row.Row = (function(_super) {
      __extends(Row, _super);

      function Row() {
        _ref6 = Row.__super__.constructor.apply(this, arguments);
        return _ref6;
      }

      Row.kls = "Row";

      Row.prototype.initialize = function() {
        /*
        The best way to understand the @details collection is
        that it is a list of cells of the XLSForm spreadsheet.
        The column name is the "key" and the value is the "value".
        We opted for a collection (rather than just saving in the attributes of
        this model) because of the various state-related attributes
        that need to be saved for each cell and this allows more room to grow.
        
        E.g.: {"key": "type", "value": "select_one colors"}
              needs to keep track of how the value was built
        */

        var curTypeDefaults, defaults, defaultsForType, defaultsUnlessDefined, key, newVals, processType, tpVal, typeDetail, vals, vk, vv,
          _this = this;

        if (this._parent) {
          defaultsUnlessDefined = this._parent.newRowDetails || $configs.newRowDetails;
          defaultsForType = this._parent.defaultsForType || $configs.defaultsForType;
        } else {
          if (typeof console !== "undefined" && console !== null) {
            console.error("Row not linked to parent survey.");
          }
          defaultsUnlessDefined = $configs.newRowDetails;
          defaultsForType = $configs.defaultsForType;
        }
        if (this.attributes.type && this.attributes.type in defaultsForType) {
          curTypeDefaults = defaultsForType[this.attributes.type];
        } else {
          curTypeDefaults = {};
        }
        defaults = _.extend({}, defaultsUnlessDefined, curTypeDefaults);
        for (key in defaults) {
          vals = defaults[key];
          if (!(key in this.attributes)) {
            newVals = {};
            for (vk in vals) {
              vv = vals[vk];
              newVals[vk] = "function" === typeof vv ? vv() : vv;
            }
            this.set(key, newVals);
          }
        }
        if (this.attributes.type === 'score') {
          new ScoreMixin(this);
        } else if (this.attributes.type === 'rank') {
          new RankMixin(this);
        }
        this.convertAttributesToRowDetails();
        typeDetail = this.get("type");
        tpVal = typeDetail.get("value");
        processType = function(rd, newType, ctxt) {
          var matchedList, p2, p3, rtp, tpid, _ref7;

          _ref7 = newType.split(" "), tpid = _ref7[0], p2 = _ref7[1], p3 = _ref7[2];
          typeDetail.set("typeId", tpid, {
            silent: true
          });
          if (p2) {
            typeDetail.set("listName", p2, {
              silent: true
            });
            matchedList = _this.getSurvey().choices.get(p2);
            if (matchedList) {
              typeDetail.set("list", matchedList);
            }
          }
          if (p3 === "or_other") {
            typeDetail.set("orOther", p3, {
              silent: true
            });
          }
          if ((rtp = $configs.lookupRowType(tpid))) {
            return typeDetail.set("rowType", rtp, {
              silent: true
            });
          } else {
            throw new Error("type `" + tpid + "` not found");
          }
        };
        processType(typeDetail, tpVal, {});
        typeDetail.on("change:value", processType);
        typeDetail.on("change:listName", function(rd, listName, ctx) {
          var rtp, typeStr;

          rtp = typeDetail.get("rowType");
          typeStr = "" + (typeDetail.get("typeId"));
          if (rtp.specifyChoice && listName) {
            typeStr += " " + listName;
          }
          if (rtp.orOtherOption && typeDetail.get("orOther")) {
            typeStr += " or_other";
          }
          return typeDetail.set({
            value: typeStr
          }, {
            silent: true
          });
        });
        return typeDetail.on("change:list", function(rd, cl, ctx) {
          var clname;

          if (typeDetail.get("rowType").specifyChoice) {
            clname = cl.get("name");
            if (!clname) {
              clname = $utils.txtid();
              cl.set("name", clname, {
                silent: true
              });
            }
            return this.set("value", "" + (this.get('typeId')) + " " + clname);
          }
        });
      };

      Row.prototype.getTypeId = function() {
        return this.get('type').get('typeId');
      };

      Row.prototype.clone = function() {
        var attributes, newRow, newRowType, options, _ref7,
          _this = this;

        attributes = {};
        options = {
          _parent: this._parent,
          add: false,
          merge: false,
          remove: false,
          silent: true
        };
        _.each(this.attributes, function(value, key) {
          return attributes[key] = _this.getValue(key);
        });
        newRow = new row.Row(attributes, options);
        newRowType = newRow.get('type');
        if ((_ref7 = newRowType.get('typeId')) === 'select_one' || _ref7 === 'select_multiple') {
          newRowType.set('list', this.getList().clone());
          newRowType.set('listName', newRowType.get('list').get('name'));
        }
        return newRow;
      };

      Row.prototype.finalize = function() {
        var existing_name, label, names;

        existing_name = this.getValue("name");
        if (!existing_name) {
          names = [];
          this.getSurvey().forEachRow(function(r) {
            var name;

            name = r.getValue("name");
            if (name) {
              return names.push(name);
            }
          });
          label = this.getValue("label");
          this.get("name").set("value", $utils.sluggifyLabel(label, names));
        }
        return this;
      };

      Row.prototype.get_type = function() {
        return $skipLogicHelpers.question_types[this.getTypeId()] || $skipLogicHelpers.question_types['default'];
      };

      Row.prototype._isSelectQuestion = function() {
        var _ref7;

        return (_ref7 = this.get('type').get('typeId')) === 'select_one' || _ref7 === 'select_multiple';
      };

      Row.prototype.getList = function() {
        var _list, _ref7;

        _list = (_ref7 = this.get('type')) != null ? _ref7.get('list') : void 0;
        if ((!_list) && this._isSelectQuestion()) {
          _list = new $choices.ChoiceList({
            name: $utils.txtid()
          });
          this.setList(_list);
        }
        return _list;
      };

      Row.prototype.setList = function(list) {
        var listToSet;

        listToSet = this.getSurvey().choices.get(list);
        if (!listToSet) {
          this.getSurvey().choices.add(list);
          listToSet = this.getSurvey().choices.get(list);
        }
        if (!listToSet) {
          throw new Error("List not found: " + list);
        }
        return this.get("type").set("list", listToSet);
      };

      Row.prototype.parse = function() {
        var key, val, _ref7, _results;

        _ref7 = this.attributes;
        _results = [];
        for (key in _ref7) {
          val = _ref7[key];
          _results.push(val.parse());
        }
        return _results;
      };

      Row.prototype.linkUp = function(ctx) {
        var key, val, _ref7, _results;

        _ref7 = this.attributes;
        _results = [];
        for (key in _ref7) {
          val = _ref7[key];
          _results.push(val.linkUp(ctx));
        }
        return _results;
      };

      return Row;

    })(row.BaseRow);
    row.RowError = (function(_super) {
      __extends(RowError, _super);

      function RowError(obj, options) {
        this._error = options.error;
        if (!global.xlfHideWarnings) {
          if (typeof console !== "undefined" && console !== null) {
            console.error("Error creating row: [" + options.error + "]", obj);
          }
        }
        RowError.__super__.constructor.call(this, obj, options);
      }

      RowError.prototype.isError = function() {
        return true;
      };

      RowError.prototype.getValue = function(what) {
        if (what in this.attributes) {
          return this.attributes[what].get('value');
        } else {
          return "[error]";
        }
      };

      return RowError;

    })(row.BaseRow);
    return row;
  });

}).call(this);


(function() {
  var __slice = [].slice,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/model.surveyFragment', ['cs!xlform/model.base', 'cs!xlform/model.row', 'cs!xlform/model.aliases', 'cs!xlform/model.utils', 'cs!xlform/model.configs', 'backbone'], function($base, $row, $aliases, $utils, $configs, Backbone) {
    var INVALID_TYPES_AT_THIS_STAGE, Rows, passFunctionToMetaModel, surveyFragment, _determineConstructorByParams, _forEachRow;

    surveyFragment = {};
    passFunctionToMetaModel = function(obj, fname) {
      obj["__" + fname] = obj[fname];
      return obj[fname] = function() {
        var args;

        args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
        return obj._meta[fname].apply(obj._meta, args);
      };
    };
    _forEachRow = function(cb, ctx) {
      if ('_beforeIterator' in this) {
        this._beforeIterator(cb, ctx);
      }
      if (!('includeErrors' in ctx)) {
        ctx.includeErrors = false;
      }
      this.rows.each(function(r, index, list) {
        if (typeof r.forEachRow === 'function') {
          if (ctx.includeGroups) {
            cb(r);
          }
          if (!ctx.flat) {
            return r.forEachRow(cb, ctx);
          }
        } else if (r.isError()) {
          if (ctx.includeErrors) {
            return cb(r);
          }
        } else {
          return cb(r);
        }
      });
      if ('_afterIterator' in this) {
        this._afterIterator(cb, ctx);
      }
    };
    surveyFragment.SurveyFragment = (function(_super) {
      __extends(SurveyFragment, _super);

      function SurveyFragment(a, b) {
        this.rows = new Rows([], {
          _parent: this
        });
        this._meta = new Backbone.Model();
        passFunctionToMetaModel(this, "set");
        passFunctionToMetaModel(this, "get");
        passFunctionToMetaModel(this, "on");
        passFunctionToMetaModel(this, "off");
        passFunctionToMetaModel(this, "trigger");
        SurveyFragment.__super__.constructor.call(this, a, b);
      }

      SurveyFragment.prototype._validate = function() {
        var isValid;

        this.clearErrors();
        isValid = true;
        if (!this.settings.get('form_id')) {
          this.addError('form id must not be empty');
          isValid = false;
        }
        if (!this.settings.get('form_title')) {
          this.addError('form title must not be empty');
          isValid = false;
        }
        return isValid;
      };

      SurveyFragment.prototype.clearErrors = function() {
        return this.errors = [];
      };

      SurveyFragment.prototype.addError = function(message) {
        return this.errors.push(message);
      };

      SurveyFragment.prototype.linkUp = function(ctx) {
        return this.invoke('linkUp', ctx);
      };

      SurveyFragment.prototype.forEachRow = function(cb, ctx) {
        if (ctx == null) {
          ctx = {};
        }
        return _forEachRow.apply(this, [cb, ctx]);
      };

      SurveyFragment.prototype.getRowDescriptors = function() {
        var descriptors;

        descriptors = [];
        this.forEachRow(function(row) {
          var descriptor;

          descriptor = {
            label: row.getValue('label'),
            name: row.getValue('name')
          };
          return descriptors.push(descriptor);
        });
        return descriptors;
      };

      SurveyFragment.prototype.findRowByCid = function(cid, options) {
        var fn, match;

        if (options == null) {
          options = {};
        }
        match = false;
        fn = function(row) {
          if (row.cid === cid) {
            match = row;
          }
          return !match;
        };
        this.forEachRow(fn, options);
        return match;
      };

      SurveyFragment.prototype.findRowByName = function(name, opts) {
        var match;

        match = false;
        this.forEachRow(function(row) {
          if ((row.getValue("name") || $utils.sluggifyLabel(row.getValue('label'))) === name) {
            match = row;
          }
          return !match;
        }, opts);
        return match;
      };

      SurveyFragment.prototype.addRowAtIndex = function(r, index) {
        return this.addRow(r, {
          at: index
        });
      };

      SurveyFragment.prototype.addRow = function(r, opts) {
        var afterRow, beforeRow, index;

        if (opts == null) {
          opts = {};
        }
        if ((afterRow = opts.after)) {
          delete opts.after;
          opts._parent = afterRow._parent;
          index = 1 + opts._parent.models.indexOf(afterRow);
          opts.at = index;
        } else if ((beforeRow = opts.before)) {
          delete opts.before;
          opts._parent = beforeRow._parent;
          index = opts._parent.models.indexOf(beforeRow);
          opts.at = index;
        } else {
          opts._parent = this.rows;
        }
        return opts._parent.add(r, opts);
      };

      SurveyFragment.prototype.detach = function() {
        this._parent.remove(this);
        return ;
      };

      SurveyFragment.prototype.remove = function(item) {
        return item.detach();
      };

      SurveyFragment.prototype._addGroup = function(opts) {
        var addOpts, first_row, grp, lowest_i, par, row, rowCids, row_i, _i, _j, _len, _len1, _ref, _ref1;

        opts._parent = this.rows;
        if (!('type' in opts)) {
          opts.type = 'group';
        }
        if (!('__rows' in opts)) {
          opts.__rows = [];
        }
        rowCids = [];
        this.forEachRow((function(r) {
          return rowCids.push(r.cid);
        }), {
          includeGroups: true,
          includeErrors: true
        });
        lowest_i = false;
        _ref = opts.__rows;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          row = _ref[_i];
          row_i = rowCids.indexOf(row.cid);
          if ((lowest_i === false) || (row_i < lowest_i)) {
            lowest_i = row_i;
            first_row = row;
          }
        }
        addOpts = {
          previous: first_row.precedingRow(),
          parent: first_row.parentRow()
        };
        _ref1 = opts.__rows;
        for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
          row = _ref1[_j];
          row.detach({
            silent: true
          });
        }
        if (opts.label == null) {
          opts.label = $configs.newGroupDetails.label.value;
        }
        grp = new surveyFragment.Group(opts);
        this.getSurvey()._insertRowInPlace(grp, addOpts);
        par = addOpts.parent || this.getSurvey().rows;
        return par.trigger('add', grp);
      };

      SurveyFragment.prototype._allRows = function() {
        var rows;

        rows = [];
        this.forEachRow((function(r) {
          if (r.constructor.kls === "Row") {
            return rows.push(r);
          }
        }), {});
        return rows;
      };

      SurveyFragment.prototype.finalize = function() {
        var _this = this;

        this.forEachRow((function(r) {
          return r.finalize();
        }), {
          includeGroups: true
        });
        return this;
      };

      return SurveyFragment;

    })($base.BaseCollection);
    surveyFragment.Group = (function(_super) {
      __extends(Group, _super);

      Group.kls = "Group";

      Group.key = "group";

      function Group(a, b) {
        var row, __rows, _i, _len;

        if (a == null) {
          a = {};
        }
        __rows = a.__rows || [];
        if (a.label === void 0) {
          a.label = '';
        }
        this._parent = a._parent;
        delete a.__rows;
        this.rows = new Rows([], {
          _parent: this
        });
        Group.__super__.constructor.call(this, a, b);
        if (__rows) {
          this.rows.add(__rows);
        }
        for (_i = 0, _len = __rows.length; _i < _len; _i++) {
          row = __rows[_i];
          row._parent = row.collection = this.rows;
        }
      }

      Group.prototype.initialize = function() {
        var grpDefaults, key, obj, typeIsRepeat;

        grpDefaults = $configs.newGroupDetails;
        for (key in grpDefaults) {
          obj = grpDefaults[key];
          if (!this.has(key)) {
            if (typeof obj.value === 'function') {
              this.set(key, obj.value(this));
            } else {
              this.set(key, obj);
            }
          }
        }
        typeIsRepeat = this.get('type') === 'repeat';
        this.set('_isRepeat', typeIsRepeat);
        return this.convertAttributesToRowDetails();
      };

      Group.prototype.addRowAtIndex = function(row, index) {
        row._parent = this.rows;
        return this.rows.add(row, {
          at: index
        });
      };

      Group.prototype._isRepeat = function() {
        var _ref;

        return !!((_ref = this.get("_isRepeat")) != null ? _ref.get("value") : void 0);
      };

      Group.prototype.autoname = function() {
        var name, new_name, slgOpts;

        name = this.getValue('name');
        if (name === (void 0) || name === '') {
          slgOpts = {
            lowerCase: false,
            stripSpaces: true,
            lrstrip: true,
            incrementorPadding: 3,
            validXmlTag: true
          };
          new_name = $utils.sluggify(this.getValue('label'), slgOpts);
          return this.setDetail('name', new_name);
        }
      };

      Group.prototype.finalize = function() {
        return this.autoname();
      };

      Group.prototype.detach = function(opts) {
        return this._parent.remove(this, opts);
      };

      Group.prototype.splitApart = function() {
        var n, row, startingIndex, _i, _len, _ref, _results;

        startingIndex = this._parent.models.indexOf(this);
        this.detach();
        _ref = this.rows.models;
        _results = [];
        for (n = _i = 0, _len = _ref.length; _i < _len; n = ++_i) {
          row = _ref[n];
          row._parent = this._parent;
          _results.push(this._parent._parent.addRowAtIndex(row, startingIndex + n));
        }
        return _results;
      };

      Group.prototype._beforeIterator = function(cb, ctxt) {
        if (ctxt.includeGroupEnds) {
          return cb(this.groupStart());
        }
      };

      Group.prototype._afterIterator = function(cb, ctxt) {
        if (ctxt.includeGroupEnds) {
          return cb(this.groupEnd());
        }
      };

      Group.prototype.forEachRow = function(cb, ctx) {
        if (ctx == null) {
          ctx = {};
        }
        return _forEachRow.apply(this, [cb, ctx]);
      };

      Group.prototype._groupOrRepeatKey = function() {
        if (this._isRepeat()) {
          return "repeat";
        } else {
          return "group";
        }
      };

      Group.prototype.groupStart = function() {
        var group;

        group = this;
        return {
          toJSON: function() {
            var k, out, val, _ref;

            out = {};
            _ref = group.attributes;
            for (k in _ref) {
              val = _ref[k];
              if (k !== '_isRepeat') {
                out[k] = val.getValue();
              }
            }
            out.type = "begin " + (group._groupOrRepeatKey());
            return out;
          }
        };
      };

      Group.prototype.groupEnd = function() {
        var group;

        group = this;
        return {
          toJSON: function() {
            return {
              type: "end " + (group._groupOrRepeatKey())
            };
          }
        };
      };

      return Group;

    })($row.BaseRow);
    INVALID_TYPES_AT_THIS_STAGE = ['begin group', 'end group', 'begin repeat', 'end repeat'];
    _determineConstructorByParams = function(obj) {
      var formSettingsTypes, type;

      formSettingsTypes = (function() {
        var key, val, _ref, _results;

        _ref = $configs.defaultSurveyDetails;
        _results = [];
        for (key in _ref) {
          val = _ref[key];
          _results.push(val.asJson.type);
        }
        return _results;
      })();
      type = obj != null ? obj.type : void 0;
      if (__indexOf.call(INVALID_TYPES_AT_THIS_STAGE, type) >= 0) {
        throw new Error("Invalid type at this stage: " + type);
      }
      if (__indexOf.call(formSettingsTypes, type) >= 0) {
        return $surveyDetail.SurveyDetail;
      } else if (type === 'score') {
        return $row.Row;
      } else if (type === 'group' || type === 'repeat') {
        return surveyFragment.Group;
      } else {
        return $row.Row;
      }
    };
    Rows = (function(_super) {
      __extends(Rows, _super);

      function Rows() {
        var args,
          _this = this;

        args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
        Rows.__super__.constructor.apply(this, args);
        this.on('add', function(a, b, c) {
          return _this._parent.getSurvey().trigger('rows-add', a, b, c);
        });
        this.on('remove', function(a, b, c) {
          return _this._parent.getSurvey().trigger('rows-remove', a, b, c);
        });
      }

      Rows.prototype.model = function(obj, ctxt) {
        var RowConstructor, e;

        RowConstructor = _determineConstructorByParams(obj);
        try {
          return new RowConstructor(obj, _.extend({}, ctxt, {
            _parent: ctxt.collection
          }));
        } catch (_error) {
          e = _error;
          return new $row.RowError(obj, _.extend({}, ctxt, {
            error: e,
            _parent: ctxt.collection
          }));
        }
      };

      Rows.prototype.comparator = function(m) {
        return m.ordinal;
      };

      return Rows;

    })($base.BaseCollection);
    return surveyFragment;
  });

}).call(this);


(function() {
  var __slice = [].slice,
    __hasProp = {}.hasOwnProperty,
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/csv', [],function() {
    var Csv, SheetedCsv, arrayToObject, arrayToObjects, asCsvCellValue, csv, parseSheetedCsv, removeTrailingNewlines, _isArray, _isString, _keys, _nativeIsArray, _nativeKeys, _remove_extra_escape_chars;

    Csv = (function() {
      function Csv(param, opts) {
        var key, row, rows, val, _i, _len, _ref,
          _this = this;

        if (opts == null) {
          opts = {};
        }
        if (_isString(param)) {
          this.string = param;
          rows = csv.toArray(this.string);
          this.rows = arrayToObjects(rows);
          this.columns = rows[0], this.rowArray = 2 <= rows.length ? __slice.call(rows, 1) : [];
        } else if (_isArray(param)) {
          this.rows = param;
          this.columns = (function() {
            var columns, key, row, _i, _len, _ref;

            columns = [];
            _ref = _this.rows;
            for (_i = 0, _len = _ref.length; _i < _len; _i++) {
              row = _ref[_i];
              for (key in row) {
                if (!__hasProp.call(row, key)) continue;
                if (__indexOf.call(columns, key) < 0) {
                  columns.push(key);
                }
              }
            }
            return columns;
          })();
          this.buildRowArray();
          this.obj = param;
        } else if (param) {
          this.columns = _isArray(param.columns) ? param.columns : [];
          if (param.rowObjects) {
            if (this.columns.length === 0) {
              _ref = param.rowObjects;
              for (_i = 0, _len = _ref.length; _i < _len; _i++) {
                row = _ref[_i];
                for (key in row) {
                  val = row[key];
                  if (!(key in columns)) {
                    this.columns.push(key);
                  }
                }
              }
            }
            this.rowArray = (function() {
              var c, _j, _len1, _ref1, _results;

              _ref1 = param.rowObjects;
              _results = [];
              for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
                row = _ref1[_j];
                _results.push((function() {
                  var _k, _len2, _ref2, _results1;

                  _ref2 = this.columns;
                  _results1 = [];
                  for (_k = 0, _len2 = _ref2.length; _k < _len2; _k++) {
                    c = _ref2[_k];
                    _results1.push(row[c]);
                  }
                  return _results1;
                }).call(_this));
              }
              return _results;
            })();
          } else {
            this.rowArray = _isArray(param.rows) ? param.rows : [];
          }
          if (param.kind != null) {
            this.kind = param.kind;
          }
          this.rows = (function() {
            var cell, i, rowObj, _j, _k, _len1, _len2, _ref1, _results;

            _ref1 = _this.rowArray;
            _results = [];
            for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
              row = _ref1[_j];
              rowObj = {};
              for (i = _k = 0, _len2 = row.length; _k < _len2; i = ++_k) {
                cell = row[i];
                if (_this.columns[i] != null) {
                  rowObj[_this.columns[i]] = cell;
                }
              }
              _results.push(rowObj);
            }
            return _results;
          })();
        } else {
          this.rows = [];
          this.columns = [];
          this.rowArray = [];
        }
      }

      Csv.prototype.buildRowArray = function() {
        var _this = this;

        return this.rowArray = (function() {
          var column, row, _i, _len, _ref, _results;

          _ref = _this.rows;
          _results = [];
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            row = _ref[_i];
            _results.push((function() {
              var _j, _len1, _ref1, _results1;

              _ref1 = this.columns;
              _results1 = [];
              for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
                column = _ref1[_j];
                _results1.push(row[column] || "");
              }
              return _results1;
            }).call(_this));
          }
          return _results;
        })();
      };

      Csv.prototype.addRow = function(r) {
        var colsChanged, column, key, val;

        colsChanged = false;
        for (key in r) {
          if (!__hasProp.call(r, key)) continue;
          val = r[key];
          if (__indexOf.call(this.columns, key) < 0) {
            colsChanged = true;
            this.columns.push(key);
          }
        }
        this.rows.push(r);
        if (colsChanged) {
          this.buildRowArray();
        } else {
          this.rowArray.push((function() {
            var _i, _len, _ref, _results;

            _ref = this.columns;
            _results = [];
            for (_i = 0, _len = _ref.length; _i < _len; _i++) {
              column = _ref[_i];
              _results.push(r[column]);
            }
            return _results;
          }).call(this));
        }
        return r;
      };

      Csv.prototype.toObjects = function(opts) {
        if (opts == null) {
          opts = {};
        }
        if (this.string) {
          return csv.toObjects(this.string, opts);
        } else if (this.rows) {
          return this.rows;
        }
      };

      Csv.prototype.toObject = function() {
        var out;

        out = {
          columns: this.columns,
          rows: this.rowArray
        };
        if (this.kind) {
          out.kind = this.kind;
        }
        return out;
      };

      Csv.prototype.toArrays = function() {
        var out, row, _i, _len, _ref;

        out = [this.columns];
        _ref = this.rowArray;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          row = _ref[_i];
          if (row.length > 0) {
            out.push(row);
          }
        }
        return out;
      };

      Csv.prototype.toString = function() {
        var cell, headRow, row;

        headRow = ((function() {
          var _i, _len, _ref, _results;

          _ref = this.columns;
          _results = [];
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            cell = _ref[_i];
            _results.push(asCsvCellValue(cell));
          }
          return _results;
        }).call(this)).join(csv.settings.delimiter);
        return headRow + "\n" + ((function() {
          var _i, _len, _ref, _results;

          _ref = this.rowArray;
          _results = [];
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            row = _ref[_i];
            _results.push(((function() {
              var _j, _len1, _results1;

              _results1 = [];
              for (_j = 0, _len1 = row.length; _j < _len1; _j++) {
                cell = row[_j];
                _results1.push(asCsvCellValue(cell));
              }
              return _results1;
            })()).join(csv.settings.delimiter));
          }
          return _results;
        }).call(this)).join("\n");
      };

      return Csv;

    })();
    csv = function(param, opts) {
      if (param instanceof Csv) {
        return param;
      } else {
        return new Csv(param, opts);
      }
    };
    _remove_extra_escape_chars = function(ss) {
      return ss.replace(/\\\\/g, '\\');
    };
    asCsvCellValue = function(cell) {
      var outstr;

      if (cell === void 0) {
        return "";
      } else if (RegExp("\\W|\\w|" + csv.settings.delimiter).test(cell)) {
        outstr = JSON.stringify("" + cell);
        return _remove_extra_escape_chars(outstr);
      } else {
        return cell;
      }
    };
    csv.fromStringArray = function(outpArr, opts) {
      var cell, outArr, row;

      if (opts == null) {
        opts = {};
      }
      outArr = (function() {
        var _i, _len, _results;

        _results = [];
        for (_i = 0, _len = outpArr.length; _i < _len; _i++) {
          row = outpArr[_i];
          _results.push(((function() {
            var _j, _len1, _results1;

            _results1 = [];
            for (_j = 0, _len1 = row.length; _j < _len1; _j++) {
              cell = row[_j];
              _results1.push(asCsvCellValue(cell));
            }
            return _results1;
          })()).join(csv.settings.delimiter));
        }
        return _results;
      })();
      return outArr.join("\n");
    };
    csv.fromArray = function(arr, opts) {
      var col, headRow, key, outpArr, row, sort, _i, _len;

      if (opts == null) {
        opts = {};
      }
      sort = !!opts.sort;
      headRow = [];
      for (_i = 0, _len = arr.length; _i < _len; _i++) {
        row = arr[_i];
        for (key in row) {
          if (!__hasProp.call(row, key)) continue;
          if (-1 === headRow.indexOf(key)) {
            headRow.push(key);
          }
        }
      }
      if (sort) {
        headRow.sort();
      }
      outpArr = (function() {
        var _j, _len1, _results;

        _results = [];
        for (_j = 0, _len1 = arr.length; _j < _len1; _j++) {
          row = arr[_j];
          _results.push((function() {
            var _k, _len2, _results1;

            _results1 = [];
            for (_k = 0, _len2 = headRow.length; _k < _len2; _k++) {
              col = headRow[_k];
              _results1.push(asCsvCellValue(row[col]));
            }
            return _results1;
          })());
        }
        return _results;
      })();
      outpArr.unshift((function() {
        var _j, _len1, _results;

        _results = [];
        for (_j = 0, _len1 = headRow.length; _j < _len1; _j++) {
          col = headRow[_j];
          _results.push(asCsvCellValue(col));
        }
        return _results;
      })());
      return csv.fromStringArray(outpArr, opts);
    };
    csv.toObjects = function(csvString) {
      return arrayToObjects(csv.toArray(csvString));
    };
    arrayToObjects = function(arr) {
      var headRow, i, key, obj, row, rows, _i, _j, _len, _len1, _results;

      headRow = arr[0], rows = 2 <= arr.length ? __slice.call(arr, 1) : [];
      _results = [];
      for (_i = 0, _len = rows.length; _i < _len; _i++) {
        row = rows[_i];
        if (!(!(row.length === 1 && row[0] === ""))) {
          continue;
        }
        obj = {};
        for (i = _j = 0, _len1 = headRow.length; _j < _len1; i = ++_j) {
          key = headRow[i];
          obj[key] = row[i];
        }
        _results.push(obj);
      }
      return _results;
    };
    csv.toObject = function(csvString, opts) {
      return arrayToObject(csv.toArray(csvString), opts);
    };
    arrayToObject = function(arr, opts) {
      var headRow, i, includeSortByKey, key, obj, out, row, rows, sbKeyVal, sortByKey, sortByKeyI, _i, _j, _len, _len1;

      if (opts == null) {
        opts = {};
      }
      headRow = arr[0], rows = 2 <= arr.length ? __slice.call(arr, 1) : [];
      sortByKey = opts.sortByKey;
      includeSortByKey = opts.includeSortByKey;
      if (!sortByKey) {
        sortByKey = headRow[0];
      }
      sortByKeyI = headRow.indexOf(sortByKey);
      out = {};
      for (_i = 0, _len = rows.length; _i < _len; _i++) {
        row = rows[_i];
        if (!(!(row.length === 1 && row[0] === ""))) {
          continue;
        }
        obj = {};
        sbKeyVal = row[sortByKeyI];
        for (i = _j = 0, _len1 = headRow.length; _j < _len1; i = ++_j) {
          key = headRow[i];
          if (i !== sortByKeyI) {
            obj[key] = row[i];
          }
        }
        if (includeSortByKey) {
          obj[sortByKey] = sbKeyVal;
        }
        out[sbKeyVal] = obj;
      }
      return out;
    };
    removeTrailingNewlines = function(str) {
      return str.replace(/(\n+)$/g, "");
    };
    csv._parse_string = function(c) {
      return JSON.parse('"' + c.replace(/\\/g, '\\\\').replace(/\\\\"/g, '\\"') + '"');
    };
    csv.toArray = function(strData) {
      var arrMatches, parsedMatch, row, rows, strDelimiter, strMatchedDelimiter, strMatchedValue;

      if (csv.settings.removeTrailingNewlines) {
        strData = removeTrailingNewlines(strData);
      }
      strDelimiter = csv.settings.delimiter;
      rows = [];
      row = [];
      csv._objPattern = RegExp("(\\" + strDelimiter + "|\\r?\\n|\\r|^)(?:\"((?:(?:[^\\\\]|\\\\\\\\|[\\\\(?=\")]\"|[\\\\(?!\")])*?))\"|([^\"\\" + strDelimiter + "\\r\\n]*))", "gi");
      while (arrMatches = csv._objPattern.exec(strData)) {
        strMatchedDelimiter = arrMatches[1];
        if (strMatchedDelimiter.length && (strMatchedDelimiter !== strDelimiter)) {
          rows.push(row);
          row = [];
        }
        if (arrMatches[2]) {
          strMatchedValue = csv._parse_string(arrMatches[2]);
        } else {
          strMatchedValue = arrMatches[3];
        }
        if (csv.settings.parseFloat && !isNaN((parsedMatch = parseFloat(strMatchedValue)))) {
          strMatchedValue = parsedMatch;
        }
        row.push(strMatchedValue);
      }
      rows.push(row);
      return rows;
    };
    SheetedCsv = (function() {
      function SheetedCsv(param, opts) {
        var _this = this;

        this._sheetIds = [];
        this._sheets = {};
        if (_isString(param)) {
          parseSheetedCsv(param, function(osids, sheets) {
            var columns, id, rows, _i, _len, _ref, _results;

            _results = [];
            for (_i = 0, _len = osids.length; _i < _len; _i++) {
              id = osids[_i];
              _ref = sheets[id], columns = _ref[0], rows = 2 <= _ref.length ? __slice.call(_ref, 1) : [];
              _results.push(_this.sheet(id, csv({
                columns: columns,
                rows: rows
              })));
            }
            return _results;
          });
        }
      }

      SheetedCsv.prototype.sheet = function(sheetId, contents) {
        if (contents == null) {
          contents = false;
        }
        if (contents) {
          if (__indexOf.call(this._sheetIds, sheetId) < 0) {
            this._sheetIds.push(sheetId);
          }
          return this._sheets[sheetId] = contents;
        } else {
          return this._sheets[sheetId];
        }
      };

      SheetedCsv.prototype.toString = function() {
        var cell, col, cols, delimiter, headRowStr, i, outp, row, rowA, sheet, sheetId, _i, _j, _k, _len, _len1, _ref, _ref1;

        outp = [];
        delimiter = csv.settings.delimiter;
        _ref = this._sheetIds;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          sheetId = _ref[_i];
          sheet = this._sheets[sheetId];
          cols = sheet.columns;
          rowA = sheet.rowArray;
          headRowStr = asCsvCellValue(sheetId);
          for (i = _j = 0, _ref1 = cols.length; 0 <= _ref1 ? _j < _ref1 : _j > _ref1; i = 0 <= _ref1 ? ++_j : --_j) {
            headRowStr += delimiter;
          }
          outp.push(headRowStr);
          outp.push(delimiter + ((function() {
            var _k, _len1, _results;

            _results = [];
            for (_k = 0, _len1 = cols.length; _k < _len1; _k++) {
              col = cols[_k];
              _results.push(asCsvCellValue(col));
            }
            return _results;
          })()).join(delimiter));
          for (_k = 0, _len1 = rowA.length; _k < _len1; _k++) {
            row = rowA[_k];
            outp.push(delimiter + ((function() {
              var _l, _len2, _results;

              _results = [];
              for (_l = 0, _len2 = row.length; _l < _len2; _l++) {
                cell = row[_l];
                _results.push(asCsvCellValue(cell));
              }
              return _results;
            })()).join(delimiter));
          }
        }
        return outp.join("\n");
      };

      return SheetedCsv;

    })();
    csv.sheeted = function(param, opts) {
      if (param instanceof SheetedCsv) {
        return param;
      } else {
        return new SheetedCsv(param, opts);
      }
    };
    parseSheetedCsv = function(shcsv, cb) {
      var cell1, curSheet, lineHasContent, orderedSheetIds, remaining, sheets, _i, _len, _ref, _ref1;

      if (cb == null) {
        cb = false;
      }
      sheets = {};
      orderedSheetIds = [];
      _ref = csv.toArray(shcsv);
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        _ref1 = _ref[_i], cell1 = _ref1[0], remaining = 2 <= _ref1.length ? __slice.call(_ref1, 1) : [];
        if (cell1) {
          curSheet = cell1;
        }
        if (!curSheet) {
          throw new Error("Sheet id must be defined in the first column and cannot be falsey");
        }
        if (__indexOf.call(orderedSheetIds, curSheet) < 0) {
          orderedSheetIds.push(curSheet);
        }
        if (!sheets[curSheet]) {
          sheets[curSheet] = [];
        }
        lineHasContent = (function() {
          var item, _j, _len1;

          for (_j = 0, _len1 = remaining.length; _j < _len1; _j++) {
            item = remaining[_j];
            if (item) {
              return true;
            }
          }
        })();
        if (lineHasContent) {
          sheets[curSheet].push(remaining);
        }
      }
      if (!cb) {
        return [orderedSheetIds, sheets];
      }
      return cb.apply(this, [orderedSheetIds, sheets]);
    };
    csv.sheeted.toObjects = function(shCsv) {
      return parseSheetedCsv(shCsv, function(osids, sheets) {
        var output, sheet, _i, _len;

        output = {};
        for (_i = 0, _len = osids.length; _i < _len; _i++) {
          sheet = osids[_i];
          output[sheet] = arrayToObjects(sheets[sheet]);
        }
        return output;
      });
    };
    csv.sheeted.toArray = function(shCsv) {
      return parseSheetedCsv(shCsv, function(osids, sheets) {
        var sheet, _i, _len, _results;

        _results = [];
        for (_i = 0, _len = osids.length; _i < _len; _i++) {
          sheet = osids[_i];
          _results.push({
            id: sheet,
            sheet: arrayToObjects(sheets[sheet])
          });
        }
        return _results;
      });
    };
    _isString = function(obj) {
      return !!(obj === '' || (obj && obj.charCodeAt && obj.substr));
    };
    _nativeIsArray = Array.isArray;
    _isArray = _nativeIsArray || function(obj) {
      return !!(obj && obj.concat && obj.unshift && !obj.callee);
    };
    _nativeKeys = Object.keys;
    _keys = _nativeKeys || function(obj) {
      var key, val, _results;

      if (_isArray(obj)) {
        return new Array(obj.length);
      }
      _results = [];
      for (key in obj) {
        val = obj[key];
        _results.push(key);
      }
      return _results;
    };
    csv.settings = {
      delimiter: ",",
      parseFloat: false,
      removeTrailingNewlines: true
    };
    return csv;
  });

}).call(this);


/*
# [inputDeserializer]
#  wrapper around methods for converting raw input into survey structure
# ______________________________________________________________________
*/


(function() {
  var __slice = [].slice;

  define('cs!xlform/model.inputDeserializer', ['underscore', 'cs!xlform/csv', 'cs!xlform/model.aliases'], function(_, csv, $aliases) {
    var deserialize, inputDeserializer, validateParse;

    inputDeserializer = function(inp, ctx) {
      var r;

      if (ctx == null) {
        ctx = {};
      }
      r = deserialize(inp, ctx);
      if (!ctx.error && ctx.validate) {
        validateParse(r, ctx);
      }
      return r;
    };
    deserialize = (function() {
      var _csv_to_params, _parse_sheets;

      _csv_to_params = function(csv_repr) {
        var cobj, out, sht;

        cobj = csv.sheeted(csv_repr);
        out = {};
        out.survey = (sht = cobj.sheet("survey")) ? sht.toObjects() : [];
        out.choices = (sht = cobj.sheet("choices")) ? sht.toObjects() : [];
        if ((sht = cobj.sheet("settings"))) {
          out.settings = sht.toObjects()[0];
        }
        return out;
      };
      _parse_sheets = function(repr) {
        var col, cols, contents, i, new_row, out_sheet, row, sheet, shtName, _i, _j, _len, _len1, _ref;

        for (shtName in repr) {
          sheet = repr[shtName];
          if (_.isArray(sheet) && sheet.length > 0 && _.isArray(sheet[0])) {
            out_sheet = [];
            cols = sheet[0], contents = 2 <= sheet.length ? __slice.call(sheet, 1) : [];
            for (_i = 0, _len = contents.length; _i < _len; _i++) {
              row = contents[_i];
              if (_.isArray(row)) {
                new_row = {};
                for (i = _j = 0, _len1 = cols.length; _j < _len1; i = ++_j) {
                  col = cols[i];
                  if (i < row.length && ((_ref = row[i]) !== (void 0) && _ref !== null)) {
                    new_row[col] = row[i];
                  }
                }
                out_sheet.push(new_row);
              } else {
                out_sheet.push(row);
              }
            }
            repr[shtName] = out_sheet;
          }
        }
        return repr;
      };
      return function(repr, ctx) {
        if (ctx == null) {
          ctx = {};
        }
        if (_.isString(repr)) {
          return _csv_to_params(repr);
        } else if (_.isObject(repr)) {
          return _parse_sheets(repr);
        } else {
          return ;
        }
      };
    })();
    validateParse = (function() {
      var requiredSheetNameList;

      requiredSheetNameList = $aliases.q.requiredSheetNameList();
      return function(repr, ctx) {
        var sheetId, sn, valid_with_sheet, _i, _len;

        if (ctx == null) {
          ctx = {};
        }
        valid_with_sheet = false;
        for (_i = 0, _len = requiredSheetNameList.length; _i < _len; _i++) {
          sheetId = requiredSheetNameList[_i];
          if (repr[sheetId]) {
            ctx.surveyType = sheetId;
            valid_with_sheet = true;
          }
        }
        if (repr['settings']) {
          ctx.settings = true;
        }
        if (repr['choices']) {
          ctx.choices = true;
        }
        if (!valid_with_sheet) {
          sn = requiredSheetNameList.join(', ');
          ctx.error = "Missing a survey sheet [" + sn + "]";
        }
        return !ctx.error;
      };
    })();
    inputDeserializer.validateParse = validateParse;
    inputDeserializer.deserialize = deserialize;
    return inputDeserializer;
  });

}).call(this);


(function() {
  define('cs!xlform/model.inputParser',['underscore', 'cs!xlform/model.aliases'], function(_, $aliases) {
    var ParsedStruct, inputParser, parseArr;

    inputParser = {};
    ParsedStruct = (function() {
      function ParsedStruct(type, atts) {
        this.type = type;
        this.atts = atts != null ? atts : {};
        this.contents = [];
      }

      ParsedStruct.prototype.push = function(item) {
        this.contents.push(item);
        return ;
      };

      ParsedStruct.prototype["export"] = function() {
        var arr, item, _i, _len, _ref;

        arr = [];
        _ref = this.contents;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          item = _ref[_i];
          if (item instanceof ParsedStruct) {
            item = item["export"]();
          }
          arr.push(item);
        }
        return _.extend({}, this.atts, {
          type: this.type,
          __rows: arr
        });
      };

      return ParsedStruct;

    })();
    parseArr = function(type, sArr) {
      var grpStack, item, _curGrp, _groupAtts, _i, _len, _popGrp, _pushGrp;

      if (type == null) {
        type = 'survey';
      }
      grpStack = [new ParsedStruct(type)];
      _pushGrp = function(type, item) {
        var grp;

        if (type == null) {
          type = 'group';
        }
        grp = new ParsedStruct(type, item);
        _curGrp().push(grp);
        return grpStack.push(grp);
      };
      _popGrp = function(closedByAtts, type) {
        var _grp;

        _grp = grpStack.pop();
        if (_grp.type !== closedByAtts.type) {
          throw new Error("mismatched group/repeat tags");
        }
        return ;
      };
      _curGrp = function() {
        var _l;

        _l = grpStack.length;
        if (_l === 0) {
          throw new Error("unmatched group/repeat");
        }
        return grpStack[_l - 1];
      };
      for (_i = 0, _len = sArr.length; _i < _len; _i++) {
        item = sArr[_i];
        _groupAtts = $aliases.q.testGroupable(item.type);
        if (_groupAtts) {
          if (_groupAtts.begin) {
            _pushGrp(_groupAtts.type, item);
          } else {
            _popGrp(_groupAtts, item.type);
          }
        } else {
          _curGrp().push(item);
        }
      }
      if (grpStack.length !== 1) {
        throw new Error("unclosed groupable set");
      }
      return _curGrp()["export"]().__rows;
    };
    inputParser.parseArr = parseArr;
    inputParser.parse = function(o) {
      if (o.survey) {
        o.survey = parseArr('survey', o.survey);
      }
      return o;
    };
    inputParser.loadChoiceLists = function(passedChoices, choices) {
      var choiceNames, choiceRow, cn, lName, tmp, _i, _j, _len, _len1, _results;

      tmp = {};
      choiceNames = [];
      for (_i = 0, _len = passedChoices.length; _i < _len; _i++) {
        choiceRow = passedChoices[_i];
        lName = choiceRow["list name"];
        if (!tmp[lName]) {
          tmp[lName] = [];
          choiceNames.push(lName);
        }
        tmp[lName].push(choiceRow);
      }
      _results = [];
      for (_j = 0, _len1 = choiceNames.length; _j < _len1; _j++) {
        cn = choiceNames[_j];
        _results.push(choices.add({
          name: cn,
          options: tmp[cn]
        }));
      }
      return _results;
    };
    return inputParser;
  });

}).call(this);


(function() {
  define('cs!xlform/model.utils.markdownTable',['cs!xlform/csv'], function(csv) {
    var markdownTable;

    markdownTable = {};
    /*
    this markdownTable is not meant to be used in production for real surveys.
    It's simply here because it provides a clean way to display xlsforms in the source code.
    */

    markdownTable.mdSurveyStructureToObject = function(md) {
      var cell, curSheet, i, rcells, row, sObj, shtName, _i, _j, _len, _len1, _pushSheet, _r, _ref, _trim;

      _trim = function(s) {
        return String(s).replace(/^\s+|\s+$/g, '');
      };
      shtName = false;
      curSheet = false;
      sObj = {};
      _pushSheet = function() {
        var cell, cols, n, row, rowObj, sheetObjs, _i, _j, _len, _len1, _ref;

        cols = curSheet[0];
        sheetObjs = [];
        _ref = curSheet.slice(1);
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          row = _ref[_i];
          rowObj = {};
          for (n = _j = 0, _len1 = row.length; _j < _len1; n = ++_j) {
            cell = row[n];
            if (cols[n]) {
              rowObj[cols[n]] = cell;
            }
          }
          sheetObjs.push(rowObj);
        }
        sObj[shtName] = sheetObjs;
        return curSheet = [];
      };
      _ref = md.split('\n');
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        row = _ref[_i];
        _r = [];
        rcells = _trim(row).split('|');
        for (i = _j = 0, _len1 = rcells.length; _j < _len1; i = ++_j) {
          cell = rcells[i];
          if (i > 0) {
            _r.push(_trim(cell));
          }
        }
        if (_r[0]) {
          if (curSheet) {
            _pushSheet();
          }
          shtName = _r[0];
          curSheet = [];
        } else if (curSheet) {
          curSheet.push(_r.slice(1, _r.length - 1));
        }
        _r;
      }
      _pushSheet();
      return sObj;
    };
    markdownTable.csvJsonToMarkdown = function(csvJson) {
      var cell, content, i, outstr, row, sheet, sheeted, shtName, _append_line_arr, _i, _j, _k, _l, _len, _len1, _len2, _len3, _lengths, _ljust, _record_max, _ref, _ref1, _ref2, _ref3, _sht;

      _lengths = [];
      _record_max = function(val, index) {
        if (!_lengths[index]) {
          _lengths[index] = 0;
        }
        if (val > _lengths[index]) {
          _lengths[index] = val;
        }
        return ;
      };
      _ljust = function(str, n) {
        var diff;

        if (!str) {
          str = '';
        }
        diff = n - str.length;
        if (diff > 0) {
          str += (new Array(diff + 1)).join(' ');
        }
        return str;
      };
      _append_line_arr = function(_arr, preceding) {
        var i, x, _i, _j, _len;

        if (preceding == null) {
          preceding = 0;
        }
        for (i = _i = 0; 0 <= preceding ? _i < preceding : _i > preceding; i = 0 <= preceding ? ++_i : --_i) {
          _arr.unshift('');
        }
        _arr.length = _lengths.length;
        for (i = _j = 0, _len = _arr.length; _j < _len; i = ++_j) {
          x = _arr[i];
          _arr[i] = _ljust(x, _lengths[i]);
        }
        outstr += "| " + (_arr.join(' | ')) + " |\n";
        return ;
      };
      sheeted = csv.sheeted();
      outstr = "\n";
      for (shtName in csvJson) {
        content = csvJson[shtName];
        _record_max(shtName.length, 0);
        _sht = sheeted.sheet(shtName, csv(content));
        _ref = content.columns;
        for (i = _i = 0, _len = _ref.length; _i < _len; i = ++_i) {
          cell = _ref[i];
          _record_max(cell.length, i + 1);
        }
        _ref1 = _sht.rowArray;
        for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
          row = _ref1[_j];
          for (i = _k = 0, _len2 = row.length; _k < _len2; i = ++_k) {
            cell = row[i];
            _record_max(cell.length, i + 1);
          }
        }
      }
      _ref2 = sheeted._sheets;
      for (shtName in _ref2) {
        sheet = _ref2[shtName];
        _append_line_arr([shtName]);
        _append_line_arr(sheet.columns, 1);
        _ref3 = sheet.rowArray;
        for (_l = 0, _len3 = _ref3.length; _l < _len3; _l++) {
          row = _ref3[_l];
          _append_line_arr(row, 1);
        }
      }
      return outstr;
    };
    return markdownTable;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; },
    __slice = [].slice;

  define('cs!xlform/model.survey', ['cs!xlform/model.base', 'cs!xlform/model.choices', 'cs!xlform/model.utils', 'cs!xlform/model.configs', 'cs!xlform/model.surveyFragment', 'cs!xlform/model.surveyDetail', 'cs!xlform/model.inputDeserializer', 'cs!xlform/model.inputParser', 'cs!xlform/model.utils.markdownTable', 'cs!xlform/csv'], function($base, $choices, $modelUtils, $configs, $surveyFragment, $surveyDetail, $inputDeserializer, $inputParser, $markdownTable, csv) {
    var Settings, Survey, _is_csv, _ref;

    Survey = (function(_super) {
      __extends(Survey, _super);

      function Survey(options, addlOpts) {
        var r, sname, _i, _len, _ref, _ref1,
          _this = this;

        if (options == null) {
          options = {};
        }
        Survey.__super__.constructor.call(this);
        this._initialParams = options;
        this.settings = new Settings(options.settings, {
          _parent: this
        });
        if (!options.settings) {
          this.settings.enable_auto_name();
        }
        if ((sname = this.settings.get("name") || options.name)) {
          this.set("name", sname);
        }
        this.newRowDetails = options.newRowDetails || $configs.newRowDetails;
        this.defaultsForType = options.defaultsForType || $configs.defaultsForType;
        this.surveyDetails = new $surveyDetail.SurveyDetails([], {
          _parent: this
        }).loadSchema(options.surveyDetailsSchema || $configs.surveyDetailSchema);
        this.choices = new $choices.ChoiceLists([], {
          _parent: this
        });
        $inputParser.loadChoiceLists(options.choices || [], this.choices);
        if (options.survey) {
          _ref = options.survey;
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            r = _ref[_i];
            if (_ref1 = r.type, __indexOf.call($configs.surveyDetailSchema.typeList(), _ref1) >= 0) {
              this.surveyDetails.importDetail(r);
            } else {
              this.rows.add(r, {
                collection: this.rows,
                silent: true,
                _parent: this.rows
              });
            }
          }
        } else {
          this.surveyDetails.importDefaults();
        }
        this.context = {
          warnings: [],
          errors: []
        };
        this.forEachRow(function(r) {
          if (typeof r.linkUp === 'function') {
            return r.linkUp(_this.context);
          }
        });
      }

      Survey.create = function(options, addlOpts) {
        if (options == null) {
          options = {};
        }
        return new Survey(options, addlOpts);
      };

      Survey.prototype.insert_row = function(row, index) {
        var name_detail, new_row, rowlist, survey;

        if (row._isCloned) {
          this.rows.add(row, {
            at: index
          });
        } else {
          this.rows.add(row.toJSON(), {
            at: index
          });
        }
        new_row = this.rows.at(index);
        survey = this.getSurvey();
        if (rowlist = row.getList()) {
          survey.choices.add({
            options: rowlist.options.toJSON()
          });
          new_row.get('type').set('list', rowlist);
        }
        name_detail = new_row.get('name');
        return name_detail.set('value', name_detail.deduplicate(survey));
      };

      Survey.prototype.insertSurvey = function(survey, index) {
        var index_incr, name_detail, row, row_i, rowlist, _i, _len, _ref;

        if (index == null) {
          index = -1;
        }
        if (index === -1) {
          index = this.rows.length;
        }
        _ref = survey.rows.models;
        for (row_i = _i = 0, _len = _ref.length; _i < _len; row_i = ++_i) {
          row = _ref[row_i];
          if (rowlist = row.getList()) {
            this.choices.add({
              name: rowlist.get("name"),
              options: rowlist.options.toJSON()
            });
          }
          name_detail = row.get('name');
          name_detail.set('value', name_detail.deduplicate(this));
          index_incr = index + row_i;
          this.rows.add(row.toJSON(), {
            at: index_incr
          });
        }
        return ;
      };

      Survey.prototype.toJSON = function(stringify, spaces) {
        var addlSheets, obj, sheet, shtName,
          _this = this;

        if (stringify == null) {
          stringify = false;
        }
        if (spaces == null) {
          spaces = 4;
        }
        obj = {};
        addlSheets = {
          choices: new $choices.ChoiceLists()
        };
        obj.survey = (function() {
          var fn, out;

          out = [];
          fn = function(r) {
            var l;

            if ('getList' in r && (l = r.getList())) {
              addlSheets.choices.add(l);
            }
            if (typeof r.export_relevant_values === 'function') {
              return r.export_relevant_values(out, addlSheets);
            } else {
              return log('no r.export_relevant_values', r);
            }
          };
          _this.forEachRow(fn, {
            includeGroupEnds: true
          });
          return out;
        })();
        for (shtName in addlSheets) {
          sheet = addlSheets[shtName];
          if (sheet.length > 0) {
            obj[shtName] = sheet.summaryObj(true);
          }
        }
        if (stringify) {
          return JSON.stringify(obj, null, spaces);
        } else {
          return obj;
        }
      };

      Survey.prototype.getSurvey = function() {
        return this;
      };

      Survey.prototype.log = function(opts) {
        var logFn, logr, tabs;

        if (opts == null) {
          opts = {};
        }
        logFn = opts.log || function() {
          var a;

          a = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
          return console.log.apply(console, a);
        };
        tabs = ['-'];
        logr = function(r) {
          if ('forEachRow' in r) {
            logFn(tabs.join('').replace(/-/g, '='), r.get('label').get('value'));
            tabs.push('-');
            r.forEachRow(logr, {
              flat: true,
              includeGroups: true
            });
            return tabs.pop();
          } else {
            return logFn(tabs.join(''), r.get('label').get('value'));
          }
        };
        this.forEachRow(logr, {
          flat: true,
          includeGroups: true
        });
        return ;
      };

      Survey.prototype.summarize = function() {
        var fn, hasGps, rowCount;

        rowCount = 0;
        hasGps = false;
        fn = function(r) {
          if (r.get('type').get('value') === 'geopoint') {
            hasGps = true;
          }
          return rowCount++;
        };
        this.forEachRow(fn, {
          includeGroups: false
        });
        return {
          rowCount: rowCount,
          hasGps: hasGps
        };
      };

      Survey.prototype._insertRowInPlace = function(row, opts) {
        var index, parent, previous;

        if (opts == null) {
          opts = {};
        }
        if (row._parent) {
          row.detach({
            silent: true
          });
        }
        index = 0;
        previous = opts.previous;
        parent = opts.parent;
        if (previous) {
          parent = previous.parentRow();
          index = parent.rows.indexOf(previous) + 1;
        }
        if (!parent) {
          parent = this;
        }
        parent.rows.add(row, {
          at: index,
          silent: true
        });
        row._parent = parent.rows;
        if (opts.event) {
          parent.rows.trigger(opts.event);
        }
      };

      Survey.prototype.prepCols = function(cols, opts) {
        var add, exclude, out;

        if (opts == null) {
          opts = {};
        }
        exclude = opts.exclude || [];
        add = opts.add || [];
        if (_.isString(exclude) || _.isString(add)) {
          throw new Error("prepCols parameters should be arrays");
        }
        out = _.filter(_.uniq(_.flatten(cols)), function(col) {
          return __indexOf.call(exclude, col) < 0;
        });
        return out.concat.apply(out, add);
      };

      Survey.prototype.toSsStructure = function() {
        var content, out, sheet, _ref;

        out = {};
        _ref = this.toCsvJson();
        for (sheet in _ref) {
          content = _ref[sheet];
          out[sheet] = content.rowObjects;
        }
        return out;
      };

      Survey.prototype.toCsvJson = function() {
        var choicesCsvJson, out,
          _this = this;

        this.finalize();
        out = {};
        out.survey = (function() {
          var addRowToORows, oCols, oRows, sd, _i, _len, _ref;

          oCols = ["name", "type", "label"];
          oRows = [];
          addRowToORows = function(r) {
            var colJson, key, val;

            colJson = r.toJSON();
            for (key in colJson) {
              if (!__hasProp.call(colJson, key)) continue;
              val = colJson[key];
              if (__indexOf.call(oCols, key) < 0) {
                oCols.push(key);
              }
            }
            return oRows.push(colJson);
          };
          _this.forEachRow(addRowToORows, {
            includeErrors: true,
            includeGroupEnds: true
          });
          _ref = _this.surveyDetails.models;
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            sd = _ref[_i];
            if (sd.get("value")) {
              addRowToORows(sd);
            }
          }
          return {
            columns: oCols,
            rowObjects: oRows
          };
        })();
        choicesCsvJson = (function() {
          var choiceList, clAtts, clName, cols, lists, option, rows, _i, _j, _len, _len1, _ref, _ref1;

          lists = new $choices.ChoiceLists();
          _this.forEachRow(function(r) {
            var list;

            if ('getList' in r && (list = r.getList())) {
              return lists.add(list);
            }
          });
          rows = [];
          cols = [];
          _ref = lists.models;
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            choiceList = _ref[_i];
            if (!choiceList.get("name")) {
              choiceList.set("name", $modelUtils.txtid(), {
                silent: true
              });
            }
            choiceList.finalize();
            clAtts = choiceList.toJSON();
            clName = clAtts.name;
            _ref1 = clAtts.options;
            for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
              option = _ref1[_j];
              cols.push(_.keys(option));
              rows.push(_.extend({}, option, {
                "list name": clName
              }));
            }
          }
          if (rows.length > 0) {
            return {
              columns: _this.prepCols(cols, {
                exclude: ['setManually'],
                add: ['list name']
              }),
              rowObjects: rows
            };
          } else {
            return false;
          }
        })();
        if (choicesCsvJson) {
          out.choices = choicesCsvJson;
        }
        out.settings = this.settings.toCsvJson();
        return out;
      };

      Survey.prototype.toMarkdown = function() {
        return $markdownTable.csvJsonToMarkdown(this.toCsvJson());
      };

      Survey.prototype.toCSV = function() {
        var content, sheeted, shtName, _ref;

        sheeted = csv.sheeted();
        _ref = this.toCsvJson();
        for (shtName in _ref) {
          content = _ref[shtName];
          sheeted.sheet(shtName, csv(content));
        }
        return sheeted.toString();
      };

      return Survey;

    })($surveyFragment.SurveyFragment);
    Survey.load = function(csv_repr, _usingSurveyLoadCsv) {
      var _deserialized, _parsed;

      if (_usingSurveyLoadCsv == null) {
        _usingSurveyLoadCsv = false;
      }
      if (_.isString(csv_repr) && !_is_csv(csv_repr)) {
        throw Error("Invalid CSV passed to form builder");
      }
      _deserialized = $inputDeserializer.deserialize(csv_repr);
      _parsed = $inputParser.parse(_deserialized);
      return new Survey(_parsed);
    };
    Survey.load.csv = function(csv_repr) {
      return Survey.load(csv_repr, true);
    };
    Survey.load.md = function(md) {
      var sObj;

      sObj = $markdownTable.mdSurveyStructureToObject(md);
      return new Survey(sObj);
    };
    _is_csv = function(csv_repr) {
      return __indexOf.call(csv_repr, '\n') >= 0 && __indexOf.call(csv_repr, ',') >= 0;
    };
    Settings = (function(_super) {
      __extends(Settings, _super);

      function Settings() {
        _ref = Settings.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Settings.prototype.validation = {
        form_title: {
          required: true,
          invalidChars: '`'
        },
        form_id: {
          required: true,
          invalidChars: '`'
        }
      };

      Settings.prototype.defaults = {
        form_title: "New form",
        form_id: "new_form"
      };

      Settings.prototype.toCsvJson = function() {
        var columns, rowObjects;

        columns = _.keys(this.attributes);
        rowObjects = [this.toJSON()];
        return {
          columns: columns,
          rowObjects: rowObjects
        };
      };

      Settings.prototype.enable_auto_name = function() {
        var _this = this;

        this.auto_name = true;
        this.on('change:form_id', function() {
          if (_this.changing_form_title) {
            return _this.changing_form_title = false;
          } else {
            return _this.auto_name = false;
          }
        });
        return this.on('change:form_title', function(model, value) {
          if (_this.auto_name) {
            _this.changing_form_title = true;
            return _this.set('form_id', $modelUtils.sluggifyLabel(value));
          }
        });
      };

      return Settings;

    })($base.BaseModel);
    return {
      Survey: Survey,
      Settings: Settings
    };
  });

}).call(this);


/*
dkobo_xlform.model[...]
*/


(function() {
  define('cs!xlform/_model', ['underscore', 'cs!xlform/model.survey', 'cs!xlform/model.utils', 'cs!xlform/model.row', 'xlform/model.rowDetails.skipLogic', 'cs!xlform/model.configs'], function(_, $survey, $utils, $row, $rowDetailsSkipLogic, $configs) {
    var model;

    model = {};
    _.extend(model, $survey, $row);
    model._keys = _.keys(model);
    model.rowDetailsSkipLogic = $rowDetailsSkipLogic;
    model.utils = $utils;
    model.configs = $configs;
    return model;
  });

}).call(this);


(function() {
  define('cs!xlform/view.choices.templates', [], function() {
    var addOptionButton;

    addOptionButton = function() {
      return "<div class=\"card__addoptions\">\n  <div class=\"card__addoptions__layer\"></div>\n    <ul><li class=\"multioptions__option  xlf-option-view xlf-option-view--depr\">\n      <div><div class=\"editable-wrapper\"><span class=\"editable editable-click\">+ Click to add another response...</span></div><code><label>Value:</label> <span>AUTOMATIC</span></code></div>\n    </li></ul>\n</div>";
    };
    return {
      addOptionButton: addOptionButton
    };
  });

}).call(this);


(function() {
  define('cs!xlform/view.row.templates', [], function() {
    var expandChoiceList, expandingSpacerHtml, groupSettingsView, groupView, rankView, rowErrorView, rowSettingsView, scoreView, selectQuestionExpansion, xlfRowView;

    expandingSpacerHtml = "<div class=\"survey__row__spacer  row clearfix expanding-spacer-between-rows expanding-spacer-between-rows--depr\">\n  <div class=\"js-expand-row-selector btn btn--addrow btn--block  btn-xs  btn-default  add-row-btn\"\n      ><i class=\"fa fa-plus\"></i></div>\n  <div class=\"line\">&nbsp;</div>\n</div>";
    groupSettingsView = function() {
      return "<section class=\"card__settings  row-extras row-extras--depr\">\n  <i class=\"card__settings-close fa fa-times js-toggle-card-settings\"></i>\n  <ul class=\"card__settings__tabs\">\n    <li class=\"heading\"><i class=\"fa fa-cog\"></i> Settings</li>\n    <li data-card-settings-tab-id=\"all\" class=\"card__settings__tabs__tab--active\">All group settings</li>\n    <li data-card-settings-tab-id=\"skip-logic\" class=\"\">Skip Logic</li>\n  </ul>\n  <div class=\"card__settings__content\">\n    <div class=\"card__settings__fields card__settings__fields--active card__settings__fields--all\">\n    </div>\n    <div class=\"card__settings__fields card__settings__fields--skip-logic\"></div>\n  </div>\n</section>";
    };
    rowSettingsView = function() {
      return "<section class=\"card__settings  row-extras row-extras--depr\">\n  <i class=\"card__settings-close fa fa-times js-toggle-card-settings\"></i>\n  <ul class=\"card__settings__tabs\">\n    <li class=\"heading\"><i class=\"fa fa-cog\"></i> Settings</li>\n    <li data-card-settings-tab-id=\"question-options\" class=\"card__settings__tabs__tab--active\">Question Options</li>\n    <li data-card-settings-tab-id=\"skip-logic\" class=\"\">Skip Logic</li>\n    <li data-card-settings-tab-id=\"validation-criteria\" class=\"\">Validation Criteria</li>\n    <li data-card-settings-tab-id=\"response-type\" class=\"card__settings__tab--response-type\">Response Type</li>\n  </ul>\n  <div class=\"card__settings__content\">\n    <ul class=\"card__settings__fields card__settings__fields--active card__settings__fields--question-options\">\n    </ul>\n\n    <ul class=\"card__settings__fields card__settings__fields--skip-logic\">\n    </ul>\n\n    <ul class=\"card__settings__fields card__settings__fields--validation-criteria\">\n    </ul>\n\n    <ul class=\"card__settings__fields card__settings__fields--response-type\">\n    </ul>\n  </div>\n</section>";
    };
    xlfRowView = function(surveyView) {
      var template;

      template = "<div class=\"survey__row__item survey__row__item--question card js-select-row\">\n  <div class=\"card__header\">\n    <div class=\"card__header--shade\"><span></span></div>\n    <div class=\"card__indicator\">\n      <div class=\"noop card__indicator__icon\"><i class=\"fa fa-fw card__header-icon\"></i></div>\n    </div>\n    <div class=\"card__text\">\n      <span class=\"card__header-title js-cancel-select-row js-cancel-sort\"></span>\n    </div>\n    <div class=\"card__buttons\">\n      <span class=\"card__buttons__button card__buttons__button--settings gray js-toggle-card-settings\" data-button-name=\"settings\"><i class=\"fa fa-cog\"></i></span>\n      <span class=\"card__buttons__button card__buttons__button--delete red js-delete-row\" data-button-name=\"delete\"><i class=\"fa fa-trash-o\"></i></span>";
      if (surveyView.features.multipleQuestions) {
        template += "<span class=\"card__buttons__button card__buttons__button--copy blue js-clone-question\" data-button-name=\"duplicate\"><i class=\"fa fa-copy\"></i></span>\n<span class=\"card__buttons__button card__buttons__button--add gray-green js-add-to-question-library\" data-button-name=\"add-to-library\"><i class=\"fa fa-folder-o\"><i class=\"fa fa-plus\"></i></i></span>";
      }
      return template + ("    </div>\n  </div>\n</div>\n" + expandingSpacerHtml);
    };
    groupView = function(g) {
      return "<div class=\"survey__row__item survey__row__item--group group card js-select-row\">\n  <header class=\"group__header\">\n    <i class=\"group__caret js-toggle-group-expansion fa fa-fw\"></i>\n    <span class=\"group__label js-cancel-select-row js-cancel-sort\">" + (g.getValue('label')) + "</span>\n      <div class=\"group__header__buttons\">\n        <span class=\"group__header__buttons__button group__header__buttons__button--settings  gray js-toggle-card-settings\"><i class=\"fa fa-cog\"></i></span>\n        <span class=\"group__header__buttons__button group__header__buttons__button--delete  red js-delete-group\"><i class=\"fa fa-trash-o\"></i></span>\n      </div>\n  </header>\n  <ul class=\"group__rows\">\n  </ul>\n</div>\n" + expandingSpacerHtml;
    };
    scoreView = function(template_args) {
      var autoname_attr, autoname_class, col, cols, fillers, namecell, row, scorelabel__name, table_html, tbody_html, thead_html, _i, _len, _ref;

      if (template_args == null) {
        template_args = {};
      }
      fillers = [];
      cols = [];
      _ref = template_args.score_choices;
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        col = _ref[_i];
        fillers.push("<td class=\"scorecell__radio\"><input type=\"radio\" disabled=\"disabled\"></td>");
        autoname_class = "";
        autoname_attr = "";
        if (col.autoname) {
          autoname_class = "scorecell__name--automatic";
          autoname_attr = "data-automatic-name=\"" + col.autoname + "\" ";
        }
        namecell = "<p class=\"scorecell__name " + autoname_class + "\" " + autoname_attr + " contenteditable=\"true\" title=\"Option value\">" + (col.name || '') + "</p>";
        cols.push("<th class=\"scorecell__col\" data-cid=\"" + col.cid + "\">\n  <span class=\"scorecell__label\" contenteditable=\"true\">" + col.label + "</span><button class=\"scorecell__delete js-delete-scorecol\">&times;</button>\n  " + namecell + "\n</th>");
      }
      thead_html = cols.join('');
      fillers = fillers.join('');
      tbody_html = (function() {
        var _j, _len1, _ref1, _results;

        _ref1 = template_args.score_rows;
        _results = [];
        for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
          row = _ref1[_j];
          autoname_attr = "";
          autoname_class = "";
          if (row.autoname) {
            autoname_class = "scorelabel__name--automatic";
            autoname_attr = "data-automatic-name=\"" + row.autoname + "\" ";
          }
          scorelabel__name = "<span class=\"scorelabel__name " + autoname_class + "\" " + autoname_attr + " contenteditable=\"true\" title=\"Row name\">" + (row.name || '') + "</span>";
          _results.push("<tr data-row-cid=\"" + row.cid + "\">\n  <td class=\"scorelabel\">\n    <span class=\"scorelabel__edit\" contenteditable=\"true\">" + row.label + "</span>\n    <button class=\"scorerow__delete js-delete-scorerow\">&times;</button>\n    <br>\n    " + scorelabel__name + "\n  </td>\n  " + fillers + "\n</tr>");
        }
        return _results;
      })();
      table_html = "<table class=\"score_preview__table\">\n  <thead>\n    <th class=\"scorecell--empty\"></th>\n    " + thead_html + "\n    <th class=\"scorecell--add\"><span>+</span></th>\n  </thead>\n  <tbody>\n    " + (tbody_html.join('')) + "\n  </tbody>\n  <tfoot>\n    <tr>\n    <td class=\"scorerow--add\"><button>+</button></td>\n    </tr>\n  </tfoot>\n</table>";
      return "<div class=\"score_preview\">\n  " + table_html + "\n</div>";
    };
    rankView = function(s, template_args) {
      var autoattr, autoclass, item, rank_constraint_message_html, rank_constraint_message_li, rank_levels_lis, rank_rows_lis;

      if (template_args == null) {
        template_args = {};
      }
      rank_levels_lis = (function() {
        var _i, _len, _ref, _results;

        _ref = template_args.rank_levels;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          item = _ref[_i];
          autoclass = "";
          autoattr = "";
          autoattr = "data-automatic-name=\"" + item.automatic + "\" ";
          if (item.set_automatic) {
            autoclass = "rank_items__name--automatic";
          }
          _results.push("<li class=\"rank_items__level\" data-cid=\"" + item.cid + "\">\n  <span class=\"rank_items__level__label\">" + item.label + "</span><button class=\"rankcell__delete js-delete-rankcell\">&times;</button>\n  <br>\n  <span class=\"rank_items__name " + autoclass + "\" " + autoattr + ">" + (item.name || '') + "</span>\n</li>");
        }
        return _results;
      })();
      rank_rows_lis = (function() {
        var _i, _len, _ref, _results;

        _ref = template_args.rank_rows;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          item = _ref[_i];
          autoclass = "";
          autoattr = "";
          autoattr = "data-automatic-name=\"" + item.automatic + "\" ";
          if (item.set_automatic) {
            autoclass = "rank_items__name--automatic";
          }
          _results.push("<li class=\"rank_items__item\" data-cid=\"" + item.cid + "\">\n  <span class=\"rank_items__item__label\">" + item.label + "</span><button class=\"rankcell__delete js-delete-rankcell\">&times;</button>\n  <br>\n  <span class=\"rank_items__name " + autoclass + "\" " + autoattr + ">" + (item.name || '') + "</span>\n</li>");
        }
        return _results;
      })();
      rank_constraint_message_html = "<li class=\"rank_items__constraint_wrap\">\n  <p class=\"rank_items__constraint_explanation\">\n    A constraint message to be read in case of error:\n  </p>\n  <p class=\"rank_items__constraint_message\">\n    " + template_args.rank_constraint_msg + "\n  </p>\n</li>";
      rank_constraint_message_li = "" + rank_constraint_message_html;
      return "<div class=\"rank_preview clearfix\">\n  <ol class=\"rank__rows\">\n    " + (rank_rows_lis.join('')) + "\n    <li class=\"rank_items__add rank_items__add--item\"><button>+</button></li>\n  </ol>\n  <ul class=\"rank__levels\">\n    " + (rank_levels_lis.join('')) + "\n    <li class=\"rank_items__add rank_items__add--level\"><button>+</button></li>\n    " + rank_constraint_message_li + "\n  </ul>\n</div>";
    };
    selectQuestionExpansion = function() {
      return "<div class=\"card--selectquestion__expansion row__multioptions js-cancel-sort\">\n  <div class=\"list-view\">\n    <ul></ul>\n  </div>\n</div>";
    };
    expandChoiceList = function() {
      return "<span class=\"card__buttons__multioptions js-toggle-row-multioptions js-cancel-select-row\"><i class=\"fa fa-fw caret\"></i></span>";
    };
    rowErrorView = function(atts) {
      return "<div class=\"card card--error\">\n  Row could not be displayed: <pre>" + atts + "</pre>\n  <em>This question could not be imported. Please re-create it manually. Please contact us at <a href=\"mailto:support@kobotoolbox.org\">support@kobotoolbox.org</a> so we can fix this bug!</em>\n</div>\n" + expandingSpacerHtml;
    };
    return {
      xlfRowView: xlfRowView,
      expandChoiceList: expandChoiceList,
      selectQuestionExpansion: selectQuestionExpansion,
      groupView: groupView,
      rowErrorView: rowErrorView,
      scoreView: scoreView,
      rankView: rankView,
      groupSettingsView: groupSettingsView,
      rowSettingsView: rowSettingsView
    };
  });

}).call(this);


(function() {
  define('cs!xlform/view.rowDetail.templates', [], function() {
    return function(that) {
      return "<code>" + that.model.key + ":</code>\n<code>" + (that.model.get("value")) + "</code>";
    };
  });

}).call(this);


(function() {
  define('cs!xlform/view.rowSelector.templates', [], function() {
    var closeRowSelectorButton, xlfRowSelector;

    xlfRowSelector = {};
    closeRowSelectorButton = "<button type=\"button\" class=\"row__questiontypes__close js-close-row-selector shrink pull-right close close-button close-button--depr\" aria-hidden=\"true\">&times;</button>";
    xlfRowSelector.line = function(name) {
      return "<div class=\"row__questiontypes row-fluid clearfix\">\n  " + closeRowSelectorButton + "\n  <input type=\"text\" value=\"" + name + "\" class=\"row__questiontypes__new-question-name js-cancel-sort\" />\n  <div class=\"row__questiontypes__list clearfix\"></div>\n</div>";
    };
    xlfRowSelector.cell = function(atts) {
      return "<div class=\"questiontypelist__item\" data-menu-item=\"" + atts.id + "\">\n  <i class=\"fa fa-" + atts.faClass + " fa-fw\"></i>\n  " + atts.label + "\n</div>";
    };
    xlfRowSelector.namer = function() {
      return "<div class=\"row__questiontypes row__questiontypes--namer\">\n  <form class=\"row__questiontypes__form\" action=\"javascript:void(0);\" >\n    <input type=\"text\" class=\"js-cancel-sort\" />\n    <button> + Add Question </button>\n  </form>\n</div>";
    };
    return xlfRowSelector;
  });

}).call(this);


(function() {
  define('cs!xlform/view.surveyApp.templates', [], function() {
    var surveyApp, surveyTemplateApp;

    surveyTemplateApp = function() {
      return "<button class=\"btn js-start-survey\">Start from Scratch</button>\n<span class=\"or\">or</span>\n<hr>\n<form action=\"/import_survey_draft\" class=\"btn btn--fileupload js-import-fileupload\">\n  <span class=\"fileinput-button\">\n    <span>Import XLS</span>\n    <input type=\"file\" name=\"files\">\n  </span>\n</form>";
    };
    surveyApp = function(surveyApp) {
      var multiple_questions, survey, type_name, warning, warnings_html, _i, _len, _ref;

      survey = surveyApp.survey;
      multiple_questions = surveyApp.features.multipleQuestions;
      if (multiple_questions) {
        type_name = "Form";
      } else {
        type_name = "Question";
      }
      warnings_html = "";
      if (surveyApp.warnings && surveyApp.warnings.length > 0) {
        warnings_html = "<div class=\"survey-warnings\">";
        _ref = surveyApp.warnings;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          warning = _ref[_i];
          warnings_html += "<p class=\"survey-warnings__warning\">" + warning + "</p>";
        }
        warnings_html += "<button class=\"survey-warnings__close-button js-close-warning\">x</button></div>";
      }
      return "<div class=\"sub-header-bar\">\n  <div class=\"container__wide\">\n    <button class=\"btn btn--utility survey-editor__action--multiquestion\" id=\"settings\"><i class=\"fa fa-cog\"></i> Form Settings</button>\n    <button class=\"btn btn--utility\" id=\"save\"><i class=\"fa fa-check-circle green\"></i> Save and Exit " + type_name + "</button>\n    <button class=\"btn btn--utility\" id=\"xlf-preview\"><i class=\"fa fa-eye\"></i> Preview " + type_name + "</button>\n    <button class=\"btn btn--utility survey-editor__action--multiquestion js-expand-multioptions--all\" ><i class=\"fa fa-caret-right\"></i> Show All Responses</button>\n    <button class=\"btn btn--utility survey-editor__action--multiquestion btn--group-questions btn--disabled js-group-rows\">Group Questions</button>\n  <button class=\"btn btn--utility pull-right survey-editor__action--multiquestion rowselector_toggle-library\" id=\"question-library\"><i class=\"fa fa-folder\"></i> Question Library</button>\n  </div>\n</div>\n<div class=\"container__fixed\">\n  <div class=\"container__wide\">\n    <div class=\"form__settings\">\n\n      <div class=\"form__settings__field form__settings__field--form_id\">\n        <label>Form ID</label>\n        <span class=\"poshytip\" title=\"Unique form name\">?</span>\n        <input type=\"text\">\n      </div>\n\n      <div class=\"form__settings__field form__settings__field--style form__settings__field--appearance\">\n        <label class=\"\">Web form style (Optional)</label>\n        <span class=\"poshytip\" title=\"This allows using different Enketo styles, e.g. 'theme-grid'\">?</span>\n        <p>\n          <select>\n            <option value=\"\">Default - single page</option>\n            <option value=\"theme-grid\">Grid theme</option>\n            <option value=\"pages\">Multiple pages</option>\n            <option value=\"theme-grid pages\">Multiple pages + Grid theme</option>\n          </select>\n        </p>\n      </div>\n\n      <div class=\"form__settings__field form__settings__field--version\">\n        <label class=\"\">Version (Optional)</label>\n        <span class=\"poshytip\" title=\"A version ID of the form\">?</span>\n        <input type=\"text\">\n      </div>\n\n      <div class=\"form__settings-meta__questions\">\n        <h4 class=\"form__settings-meta__questions-title\">Hidden meta questions to include in your form to help with analysis</h4>\n        <div class=\"stats  row-details settings__first-meta\" id=\"additional-options\"></div>\n        <h4 class=\"form__settings-meta__questions-title\">Meta questions for collecting with cell phones</h4>\n        <div class=\"stats  row-details settings__second-meta\" id=\"additional-options\"></div>\n      </div>\n\n      <div class=\"form__settings-submission-url bleeding-edge\">\n        <label class=\"\">Manual submission URL (advanced)</label>\n        <span class=\"poshytip\" title=\"The specific server instance where the data should go to - optional\">?</span>\n        <div><span class=\"editable  editable-click\">http://kobotoolbox.org/data/longish_username</span></div>\n      </div>\n\n      <div class=\"form__settings-public-key bleeding-edge\">\n        <label class=\"\">Public Key</label>\n        <span class=\"poshytip\" title=\"The encryption key used for secure forms - optional\">?</span>\n        <span class=\"editable  editable-click\">12345-232</span>\n      </div>\n\n    </div>\n  </div>\n</div>\n<header class=\"survey-header\">\n  <p class=\"survey-header__description\" hidden>\n    <hgroup class=\"survey-header__inner container\">\n      <h1 class=\"survey-header__title\">\n        <span class=\"form-title\">" + (survey.settings.get("form_title")) + "</span>\n      </h1>\n    </hgroup>\n  </p>\n</header>\n" + warnings_html + "\n<div class=\"survey-editor form-editor-wrap container\">\n  <ul class=\"-form-editor survey-editor__list\">\n    <li class=\"survey-editor__null-top-row empty\">\n      <p class=\"survey-editor__message well\">\n        <b>This form is currently empty.</b><br>\n        You can add questions, notes, prompts, or other fields by clicking on the \"+\" sign below.\n      </p>\n      <div class=\"survey__row__spacer  expanding-spacer-between-rows expanding-spacer-between-rows--depr\">\n        <div class=\"btn btn--block btn--addrow js-expand-row-selector   add-row-btn add-row-btn--depr\">\n          <i class=\"fa fa-plus\"></i>\n        </div>\n        <div class=\"line\">&nbsp;</div>\n      </div>\n    </li>\n  </ul>\n</div>";
    };
    return {
      surveyTemplateApp: surveyTemplateApp,
      surveyApp: surveyApp
    };
  });

}).call(this);


(function() {
  define('cs!xlform/view.surveyDetails.templates', [], function() {
    var xlfSurveyDetailView;

    xlfSurveyDetailView = function(model) {
      return "<label title=\"" + (model.get("description") || '') + "\">\n  <input type=\"checkbox\">\n  " + (model.get("label")) + "\n</label>";
    };
    return {
      xlfSurveyDetailView: xlfSurveyDetailView
    };
  });

}).call(this);


(function() {
  var __slice = [].slice;

  define('cs!xlform/view.templates', ['cs!xlform/view.choices.templates', 'cs!xlform/view.row.templates', 'cs!xlform/view.rowDetail.templates', 'cs!xlform/view.rowSelector.templates', 'cs!xlform/view.surveyApp.templates', 'cs!xlform/view.surveyDetails.templates'], function(choices_templates, row_templates, rowDetail_templates, rowSelector_templates, surveyApp_templates, surveyDetails_templates) {
    var $$render, templates;

    templates = {
      choices: choices_templates,
      row: row_templates,
      rowDetail: rowDetail_templates,
      rowSelector: rowSelector_templates,
      surveyApp: surveyApp_templates,
      surveyDetails: surveyDetails_templates
    };
    templates['xlfListView.addOptionButton'] = choices_templates.addOptionButton;
    templates['xlfSurveyDetailView'] = surveyDetails_templates.xlfSurveyDetailView;
    templates['row.rowErrorView'] = row_templates.rowErrorView;
    templates['row.xlfRowView'] = row_templates.xlfRowView;
    templates['row.scoreView'] = row_templates.scoreView;
    templates['row.rankView'] = row_templates.rankView;
    templates['surveyApp'] = surveyApp_templates.surveyApp;
    templates['xlfRowSelector.line'] = rowSelector_templates.line;
    templates['xlfRowSelector.cell'] = rowSelector_templates.cell;
    templates['xlfRowSelector.namer'] = rowSelector_templates.namer;
    templates['xlfDetailView'] = rowDetail_templates;
    $$render = function() {
      var id, params, template;

      id = arguments[0], params = 2 <= arguments.length ? __slice.call(arguments, 1) : [];
      template = templates[id];
      if (!template) {
        console.log(typeof choices_templates, _.keys(choices_templates));
        throw new Error("Template not available: '" + id + "'");
      }
      if ('function' !== typeof template) {
        throw new Error("Template not a function: '" + id + "'");
      }
      return template.apply(null, params);
    };
    templates.$$render = $$render;
    return templates;
  });

}).call(this);


/*
This is the view for the survey-wide details that appear at the bottom
of the survey. Examples: "imei", "start", "end"
*/


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/view.surveyDetails', ['backbone', 'cs!xlform/view.templates'], function(Backbone, $viewTemplates) {
    var SurveyDetailView;

    SurveyDetailView = (function(_super) {
      __extends(SurveyDetailView, _super);

      SurveyDetailView.prototype.className = "survey-header__option";

      SurveyDetailView.prototype.events = {
        "change input": "changeChkValue"
      };

      SurveyDetailView.prototype.initialize = function(_arg) {
        this.model = _arg.model;
      };

      SurveyDetailView.prototype.render = function() {
        this.$el.append($viewTemplates.$$render('xlfSurveyDetailView', this.model));
        this.chk = this.$el.find("input");
        if (this.model.get("value")) {
          this.chk.prop("checked", true);
        }
        this.changeChkValue();
        return this;
      };

      SurveyDetailView.prototype.changeChkValue = function() {
        if (this.chk.prop("checked")) {
          this.$el.addClass("active");
          return this.model.set("value", true);
        } else {
          this.$el.removeClass("active");
          return this.model.set("value", false);
        }
      };

      function SurveyDetailView(options) {
        SurveyDetailView.__super__.constructor.apply(this, arguments);
        this.selector = options.selector;
      }

      SurveyDetailView.prototype.attach_to = function(destination) {
        return destination.find(this.selector).append(this.el);
      };

      return SurveyDetailView;

    })(Backbone.View);
    return {
      SurveyDetailView: SurveyDetailView
    };
  });

}).call(this);

var global = this;

define('jquery', [], function(){
  if(!global.jQuery) {
    global.process || global.console && global.console.error("jQuery has not been loaded into the page. Library will not work properly.")
  }
  return global.jQuery;
});


/*
This file is intended to ensure that modules that use external plugins
have access to those plugins and a proper error message is
displayed.
*/


(function() {
  define('cs!xlform/view.pluggedIn.backboneView', ['backbone', 'jquery'], function(Backbone, $) {
    var errorMessageUnlessExists, missingPlugins;

    missingPlugins = [];
    errorMessageUnlessExists = function(base, param, message) {
      if (!base[param]) {
        return missingPlugins.push("'" + param + "': '" + message + "'");
      }
    };
    if (missingPlugins.length > 0) {
      throw new Error("Missing plugin(s): {" + (missingPlugins.join(', ')) + "}");
    }
    return Backbone.View;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/view.icons', ['backbone'], function(Backbone) {
    var QtypeIcon, QtypeIconCollection, iconDetails, _ref, _ref1;

    iconDetails = [
      {
        label: "Select One",
        faClass: "dot-circle-o",
        grouping: "r1",
        id: "select_one"
      }, {
        label: "Select Many",
        faClass: "list-ul",
        grouping: "r1",
        id: "select_multiple"
      }, {
        label: "Text",
        faClass: "lato-text",
        grouping: "r1",
        id: "text"
      }, {
        label: "Number",
        faClass: "lato-integer",
        grouping: "r1",
        id: "integer"
      }, {
        label: "Decimal",
        faClass: "lato-decimal",
        grouping: "r2",
        id: "decimal"
      }, {
        label: "Date",
        faClass: "calendar",
        grouping: "r2",
        id: "date"
      }, {
        label: "Time",
        faClass: "clock-o",
        grouping: "r2",
        id: "time"
      }, {
        label: "Date & time",
        faClass: "calendar clock-over",
        grouping: "r2",
        id: "datetime"
      }, {
        label: "GPS",
        faClass: "map-marker",
        grouping: "r3",
        id: "geopoint"
      }, {
        label: "Photo",
        faClass: "picture-o",
        grouping: "r3",
        id: "image"
      }, {
        label: "Audio",
        faClass: "volume-up",
        grouping: "r3",
        id: "audio"
      }, {
        label: "Video",
        faClass: "video-camera",
        grouping: "r3",
        id: "video"
      }, {
        label: "Note",
        faClass: "bars",
        grouping: "r4",
        id: "note"
      }, {
        label: "Barcode",
        faClass: "barcode",
        grouping: "r4",
        id: "barcode"
      }, {
        label: "Acknowledge",
        faClass: "check-square-o",
        grouping: "r4",
        id: "acknowledge"
      }, {
        label: "Calculate",
        faClass: "lato-calculate",
        grouping: "r4",
        id: "calculate"
      }, {
        label: "Matrix / Rating",
        faClass: "th",
        grouping: "r5",
        id: "score"
      }, {
        label: "Ranking",
        faClass: "sort-amount-desc",
        grouping: "r5",
        id: "rank"
      }
    ];
    QtypeIcon = (function(_super) {
      __extends(QtypeIcon, _super);

      function QtypeIcon() {
        _ref = QtypeIcon.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      QtypeIcon.prototype.defaults = {
        faClass: "question-circle"
      };

      return QtypeIcon;

    })(Backbone.Model);
    QtypeIconCollection = (function(_super) {
      __extends(QtypeIconCollection, _super);

      function QtypeIconCollection() {
        _ref1 = QtypeIconCollection.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      QtypeIconCollection.prototype.model = QtypeIcon;

      QtypeIconCollection.prototype.grouped = function() {
        var grp_keys,
          _this = this;

        if (!this._groups) {
          this._groups = [];
          grp_keys = [];
          this.each(function(model) {
            var grping, ii;

            grping = model.get("grouping");
            if (__indexOf.call(grp_keys, grping) < 0) {
              grp_keys.push(grping);
            }
            ii = grp_keys.indexOf(grping);
            _this._groups[ii] || (_this._groups[ii] = []);
            return _this._groups[ii].push(model);
          });
        }
        return _.zip.apply(null, this._groups);
      };

      return QtypeIconCollection;

    })(Backbone.Collection);
    return new QtypeIconCollection(iconDetails);
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/view.rowSelector', ['backbone', 'cs!xlform/view.pluggedIn.backboneView', 'cs!xlform/view.templates', 'cs!xlform/view.icons'], function(Backbone, $baseView, $viewTemplates, $icons) {
    var viewRowSelector, _ref;

    viewRowSelector = {};
    viewRowSelector.RowSelector = (function(_super) {
      __extends(RowSelector, _super);

      function RowSelector() {
        _ref = RowSelector.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      RowSelector.prototype.events = {
        "click .js-close-row-selector": "shrink"
      };

      RowSelector.prototype.initialize = function(opts) {
        this.options = opts;
        this.ngScope = opts.ngScope;
        this.reversible = opts.reversible;
        this.button = this.$el.find(".btn").eq(0);
        this.line = this.$el.find(".line");
        if (opts.action === "click-add-row") {
          return this.expand();
        }
      };

      RowSelector.prototype.expand = function() {
        var $namer_form;

        this.$el.parents('.survey-editor__null-top-row--hidden').removeClass('survey-editor__null-top-row--hidden');
        this.show_namer();
        $namer_form = this.$el.find('.row__questiontypes__form');
        $namer_form.on('submit', _.bind(this.show_picker, this));
        $namer_form.find('button').on('click', function(evt) {
          evt.preventDefault();
          return $namer_form.submit();
        });
        return this.$('input').eq(0).focus();
      };

      RowSelector.prototype.show_namer = function() {
        var $surveyViewEl,
          _this = this;

        $surveyViewEl = this.options.surveyView.$el;
        $surveyViewEl.find('.line.expanded').removeClass('expanded').empty();
        $surveyViewEl.find('.btn--hidden').removeClass('btn--hidden');
        this.button.addClass('btn--hidden');
        this.line.addClass("expanded");
        this.line.parents(".survey-editor__null-top-row").addClass("expanded");
        this.line.css("height", "inherit");
        this.line.html($viewTemplates.$$render('xlfRowSelector.namer'));
        $.scrollTo(this.line, 200, {
          offset: -300
        });
        if (this.options.surveyView.features.multipleQuestions) {
          $(window).on('keydown.cancel_add_question', function(evt) {
            if (evt.which === 27) {
              return _this.shrink();
            }
          });
          return $('body').on('mousedown.cancel_add_question', function(evt) {
            if ($(evt.target).closest('.line.expanded').length === 0) {
              return _this.shrink();
            }
          });
        } else {
          $(window).on('keydown.cancel_add_question', function(evt) {
            if (evt.which === 27) {
              evt.preventDefault();
              return _this.$('input').eq(0).focus();
            }
          });
          return $('body').on('mousedown.cancel_add_question', function(evt) {
            if ($(evt.target).closest('.line.expanded').length === 0) {
              evt.preventDefault();
              return _this.$('input').eq(0).focus();
            }
          });
        }
      };

      RowSelector.prototype.show_picker = function(evt) {
        var $menu, i, menurow, mitem, mrow, _i, _j, _len, _len1, _ref1;

        evt.preventDefault();
        this.question_name = this.line.find('input').val();
        this.line.empty();
        $.scrollTo(this.line, 200, {
          offset: -300
        });
        this.line.html($viewTemplates.$$render('xlfRowSelector.line', ""));
        this.line.find('.row__questiontypes__new-question-name').val(this.question_name);
        $menu = this.line.find(".row__questiontypes__list");
        _ref1 = $icons.grouped();
        for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
          mrow = _ref1[_i];
          menurow = $("<div>", {
            "class": "questiontypelist__row"
          }).appendTo($menu);
          for (i = _j = 0, _len1 = mrow.length; _j < _len1; i = ++_j) {
            mitem = mrow[i];
            if (mitem) {
              menurow.append($viewTemplates.$$render('xlfRowSelector.cell', mitem.attributes));
            }
          }
        }
        return this.$('.questiontypelist__item').click(_.bind(this.selectMenuItem, this));
      };

      RowSelector.prototype.shrink = function() {
        var _this = this;

        $(window).off('keydown.cancel_add_question');
        $('body').off('mousedown.cancel_add_question');
        this.line.find("div").eq(0).fadeOut(250, function() {
          return _this.line.empty();
        });
        this.line.parents(".survey-editor__null-top-row").removeClass("expanded");
        this.line.removeClass("expanded");
        this.line.animate({
          height: "0"
        });
        if (this.reversible) {
          return this.button.removeClass('btn--hidden');
        }
      };

      RowSelector.prototype.hide = function() {
        this.button.removeClass('btn--hidden');
        this.line.empty().removeClass("expanded").css({
          "height": 0
        });
        return this.line.parents(".survey-editor__null-top-row").removeClass("expanded").addClass("survey-editor__null-top-row--hidden");
      };

      RowSelector.prototype.selectMenuItem = function(evt) {
        var newRow, options, rowBefore, rowDetails, rowType, survey, value, _ref1,
          _this = this;

        this.question_name = this.line.find('input').val();
        $('select.skiplogic__rowselect').select2('destroy');
        rowType = $(evt.target).closest('.questiontypelist__item').data("menuItem");
        value = (this.question_name || 'New Question').replace(/\t/g, ' ');
        rowDetails = {
          type: rowType
        };
        if (rowType === 'calculate') {
          rowDetails.calculation = value;
        } else {
          rowDetails.label = value;
        }
        options = {};
        if ((rowBefore = (_ref1 = this.options.spawnedFromView) != null ? _ref1.model : void 0)) {
          options.after = rowBefore;
          survey = rowBefore.getSurvey();
        } else {
          survey = this.options.survey;
          options.at = 0;
        }
        newRow = survey.addRow(rowDetails, options);
        newRow.linkUp({
          warnings: [],
          errors: []
        });
        this.hide();
        return this.options.surveyView.reset().then(function() {
          var view;

          view = _this.options.surveyView.getViewForRow(newRow);
          return $.scrollTo(view.$el, 200, {
            offset: -300
          });
        });
      };

      return RowSelector;

    })($baseView);
    return viewRowSelector;
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/view.choices', ['backbone', 'cs!xlform/model.choices', 'cs!xlform/model.utils', 'cs!xlform/view.pluggedIn.backboneView', 'cs!xlform/view.templates', 'cs!xlform/view.utils'], function(Backbone, $choices, $modelUtils, $baseView, $viewTemplates, $viewUtils) {
    var ListView, OptionView, _ref, _ref1;

    ListView = (function(_super) {
      __extends(ListView, _super);

      function ListView() {
        _ref = ListView.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      ListView.prototype.initialize = function(_arg) {
        this.rowView = _arg.rowView, this.model = _arg.model;
        this.list = this.model;
        this.row = this.rowView.model;
        $($.parseHTML($viewTemplates.row.selectQuestionExpansion())).insertAfter(this.rowView.$('.card__header'));
        this.$el = this.rowView.$(".list-view");
        return this.ulClasses = this.$("ul").prop("className");
      };

      ListView.prototype.render = function() {
        var btn, cardText, i, option, _i, _len, _ref1,
          _this = this;

        cardText = this.rowView.$el.find('.card__text');
        if (cardText.find('.card__buttons__multioptions.js-expand-multioptions').length === 0) {
          cardText.prepend($.parseHTML($viewTemplates.row.expandChoiceList()));
        }
        this.$el.html((this.ul = $("<ul>", {
          "class": this.ulClasses
        })));
        if (this.row.get("type").get("rowType").specifyChoice) {
          _ref1 = this.model.options.models;
          for (i = _i = 0, _len = _ref1.length; _i < _len; i = ++_i) {
            option = _ref1[i];
            new OptionView({
              model: option,
              cl: this.model
            }).render().$el.appendTo(this.ul);
          }
          if (i === 0) {
            while (i < 2) {
              this.addEmptyOption("Option " + (++i));
            }
          }
          this.$el.removeClass("hidden");
        } else {
          this.$el.addClass("hidden");
        }
        this.ul.sortable({
          axis: "y",
          cursor: "move",
          distance: 5,
          items: "> li",
          placeholder: "option-placeholder",
          opacity: 0.9,
          scroll: false,
          deactivate: function() {
            if (_this.hasReordered) {
              _this.reordered();
            }
            return true;
          },
          change: function() {
            return _this.hasReordered = true;
          }
        });
        btn = $($viewTemplates.$$render('xlfListView.addOptionButton'));
        btn.click(function() {
          i = _this.model.options.length;
          return _this.addEmptyOption("Option " + (i + 1));
        });
        this.$el.append(btn);
        return this;
      };

      ListView.prototype.addEmptyOption = function(label) {
        var emptyOpt, lis;

        emptyOpt = new $choices.Option({
          label: label
        });
        this.model.options.add(emptyOpt);
        new OptionView({
          model: emptyOpt,
          cl: this.model
        }).render().$el.appendTo(this.ul);
        lis = this.ul.find('li');
        if (lis.length === 2) {
          return lis.find('.js-remove-option').removeClass('hidden');
        }
      };

      ListView.prototype.reordered = function(evt, ui) {
        var id, ids, n, _i, _len,
          _this = this;

        ids = [];
        this.ul.find("> li").each(function(i, li) {
          var lid;

          lid = $(li).data("optionId");
          if (lid) {
            return ids.push(lid);
          }
        });
        for (n = _i = 0, _len = ids.length; _i < _len; n = ++_i) {
          id = ids[n];
          this.model.options.get(id).set("order", n, {
            silent: true
          });
        }
        this.model.options.comparator = "order";
        this.model.options.sort();
        return this.hasReordered = false;
      };

      return ListView;

    })($baseView);
    OptionView = (function(_super) {
      __extends(OptionView, _super);

      function OptionView() {
        _ref1 = OptionView.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      OptionView.prototype.tagName = "li";

      OptionView.prototype.className = "multioptions__option  xlf-option-view xlf-option-view--depr";

      OptionView.prototype.events = {
        "keyup input": "keyupinput",
        "click .js-remove-option": "remove"
      };

      OptionView.prototype.initialize = function(options) {
        this.options = options;
      };

      OptionView.prototype.render = function() {
        var _this = this;

        this.t = $("<i class=\"fa fa-trash-o js-remove-option\">");
        this.pw = $("<div class=\"editable-wrapper js-cancel-select-row\">");
        this.p = $("<span class=\"js-cancel-select-row\">");
        this.c = $("<code><label>Value:</label> <span class=\"js-cancel-select-row\">AUTOMATIC</span></code>");
        this.d = $('<div>');
        if (this.model) {
          this.p.html(this.model.get("label") || 'Empty');
          this.$el.attr("data-option-id", this.model.cid);
          $('span', this.c).html(this.model.get("name"));
          this.model.set('setManually', true);
        } else {
          this.model = new $choices.Option();
          this.options.cl.options.add(this.model);
          this.p.html("Option " + (1 + this.options.i)).addClass("preliminary");
        }
        $viewUtils.makeEditable(this, this.model, this.p, {
          edit_callback: _.bind(this.saveValue, this)
        });
        this.n = $('span', this.c);
        $viewUtils.makeEditable(this, this.model, this.n, {
          edit_callback: function(val) {
            var other_names;

            other_names = _this.options.cl.getNames();
            if ((_this.model.get('name') != null) && val.toLowerCase() === _this.model.get('name').toLowerCase()) {
              other_names.splice(_.indexOf(other_names, _this.model.get('name')), 1);
            }
            if (val === '') {
              _this.model.unset('name');
              _this.model.set('setManually', false);
              val = 'AUTOMATIC';
              _this.$el.trigger("choice-list-update", _this.options.cl.cid);
            } else {
              val = $modelUtils.sluggify(val, {
                preventDuplicates: other_names,
                lowerCase: false,
                lrstrip: true,
                incrementorPadding: false,
                characterLimit: 14,
                validXmlTag: false,
                nonWordCharsExceptions: '+-.'
              });
              _this.model.set('name', val);
              _this.model.set('setManually', true);
              _this.$el.trigger("choice-list-update", _this.options.cl.cid);
            }
            return {
              newValue: val
            };
          }
        });
        this.pw.html(this.p);
        this.pw.on('click', function(event) {
          if (!_this.p.is(':hidden') && event.target !== _this.p[0]) {
            return _this.p.click();
          }
        });
        this.d.append(this.pw);
        this.d.append(this.t);
        this.d.append(this.c);
        this.$el.html(this.d);
        return this;
      };

      OptionView.prototype.keyupinput = function(evt) {
        var ifield;

        ifield = this.$("input.inplace_field");
        if (evt.keyCode === 8 && ifield.hasClass("empty")) {
          ifield.blur();
        }
        if (ifield.val() === "") {
          return ifield.addClass("empty");
        } else {
          return ifield.removeClass("empty");
        }
      };

      OptionView.prototype.remove = function() {
        var $parent, lis;

        $parent = this.$el.parent();
        this.$el.remove();
        this.model.destroy();
        lis = $parent.find('li');
        if (lis.length === 1) {
          return lis.find('.js-remove-option').addClass('hidden');
        }
      };

      OptionView.prototype.saveValue = function(nval) {
        var other_names, sluggifyOpts;

        if (!("" + nval).match(/\S/)) {
          nval = false;
        }
        if (nval) {
          nval = nval.replace(/\t/g, ' ');
          this.model.set("label", nval, {
            silent: true
          });
          other_names = this.options.cl.getNames();
          if (!this.model.get('setManually')) {
            sluggifyOpts = {
              preventDuplicates: other_names,
              lowerCase: false,
              stripSpaces: true,
              lrstrip: true,
              incrementorPadding: 3,
              validXmlTag: true
            };
            this.model.set("name", $modelUtils.sluggify(nval, sluggifyOpts));
          }
          this.$el.trigger("choice-list-update", this.options.cl.cid);
        } else {
          return {
            newValue: this.model.get("label")
          };
        }
      };

      return OptionView;

    })($baseView);
    return {
      ListView: ListView,
      OptionView: OptionView
    };
  });

}).call(this);


(function() {
  var __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  define('cs!xlform/view.rowDetail', ['cs!xlform/model.utils', 'cs!xlform/model.configs', 'cs!xlform/view.utils', 'cs!xlform/view.icons', 'cs!xlform/view.rowDetail.SkipLogic', 'cs!xlform/view.templates'], function($modelUtils, $configs, $viewUtils, $icons, $viewRowDetailSkipLogic, $viewTemplates) {
    var viewRowDetail, _ref;

    viewRowDetail = {};
    viewRowDetail.DetailView = (function(_super) {
      __extends(DetailView, _super);

      function DetailView() {
        _ref = DetailView.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      /*
      The DetailView class is a base class for details
      of each row of the XLForm. When the view is initialized,
      a mixin from "DetailViewMixins" is applied.
      */


      DetailView.prototype.className = "card__settings__fields__field  dt-view dt-view--depr";

      DetailView.prototype.initialize = function(_arg) {
        this.rowView = _arg.rowView;
        if (!this.model.key) {
          throw new Error("RowDetail does not have key");
        }
        this.extraClass = "xlf-dv-" + this.model.key;
        _.extend(this, viewRowDetail.DetailViewMixins[this.model.key] || viewRowDetail.DetailViewMixins["default"]);
        return this.$el.addClass(this.extraClass);
      };

      DetailView.prototype.render = function() {
        var rendered;

        rendered = this.html();
        if (rendered) {
          this.$el.html(rendered);
        }
        this.afterRender && this.afterRender();
        return this;
      };

      DetailView.prototype.html = function() {
        return $viewTemplates.$$render('xlfDetailView', this);
      };

      DetailView.prototype.listenForCheckboxChange = function(opts) {
        var $el, changing, el, reflectValueInEl,
          _this = this;

        if (opts == null) {
          opts = {};
        }
        el = opts.el || this.$('input[type=checkbox]').get(0);
        $el = $(el);
        changing = false;
        reflectValueInEl = function() {
          var val;

          if (!changing) {
            val = _this.model.get('value');
            if (val === true || __indexOf.call($configs.truthyValues, val) >= 0) {
              return $el.prop('checked', true);
            }
          }
        };
        this.model.on('change:value', reflectValueInEl);
        reflectValueInEl();
        return $el.on('change', function() {
          changing = true;
          _this.model.set('value', $el.prop('checked'));
          return changing = false;
        });
      };

      DetailView.prototype.listenForInputChange = function(opts) {
        var $el, changeModelValue, el, inTransition, inputType, reflectValueInEl, transformFn,
          _this = this;

        if (opts == null) {
          opts = {};
        }
        el = opts.el || this.$('input').get(0);
        $el = $(el);
        transformFn = opts.transformFn || false;
        inputType = opts.inputType;
        inTransition = false;
        changeModelValue = function($elVal) {
          if (!inTransition) {
            inTransition = true;
            _this.model.set('value', $elVal);
            reflectValueInEl(true);
            return inTransition = false;
          }
        };
        reflectValueInEl = function(force) {
          var modelVal;

          if (force == null) {
            force = false;
          }
          if (force || !inTransition) {
            modelVal = _this.model.get('value');
            if (inputType === 'checkbox') {
              if (!_.isBoolean(modelVal)) {
                modelVal = __indexOf.call($configs.truthyValues, modelVal) >= 0;
              }
              return $el.prop('checked', modelVal);
            } else {
              return $el.val(modelVal);
            }
          }
        };
        reflectValueInEl();
        this.model.on('change:value', reflectValueInEl);
        $el.on('change', function() {
          var $elVal;

          $elVal = $el.val();
          if (transformFn) {
            $elVal = transformFn($elVal);
          }
          return changeModelValue($elVal);
        });
      };

      DetailView.prototype._insertInDOM = function(where, how) {
        return where[how || 'append'](this.el);
      };

      DetailView.prototype.insertInDOM = function(rowView) {
        return this._insertInDOM(rowView.defaultRowDetailParent);
      };

      return DetailView;

    })(Backbone.View);
    viewRowDetail.Templates = {
      textbox: function(cid, key, key_label, input_class) {
        if (key_label == null) {
          key_label = key;
        }
        if (input_class == null) {
          input_class = '';
        }
        return this.field("<input type=\"text\" name=\"" + key + "\" id=\"" + cid + "\" class=\"" + input_class + "\" />", cid, key_label);
      },
      checkbox: function(cid, key, key_label, input_label) {
        if (key_label == null) {
          key_label = key;
        }
        if (input_label == null) {
          input_label = 'Yes';
        }
        return this.field("<input type=\"checkbox\" name=\"" + key + "\" id=\"" + cid + "\"/> <label for=\"" + cid + "\">" + input_label + "</label>", cid, key_label);
      },
      dropdown: function(cid, key, values, key_label) {
        var select, value, _i, _len;

        if (key_label == null) {
          key_label = key;
        }
        select = "<select id=\"" + cid + "\">";
        for (_i = 0, _len = values.length; _i < _len; _i++) {
          value = values[_i];
          select += "<option value=\"" + value + "\">" + value + "</option>";
        }
        select += "</select>";
        return this.field(select, cid, key_label);
      },
      field: function(input, cid, key_label) {
        return "<div class=\"card__settings__fields__field\">\n  <label for=\"" + cid + "\">" + key_label + ":</label>\n  <span class=\"settings__input\">\n    " + input + "\n  </span>\n</div>";
      }
    };
    viewRowDetail.DetailViewMixins = {};
    viewRowDetail.DetailViewMixins.type = {
      html: function() {
        return false;
      },
      insertInDOM: function(rowView) {
        var faClass, typeStr, _ref1;

        typeStr = this.model.get("typeId");
        if (!(this.model._parent.constructor.kls === "Group")) {
          faClass = (_ref1 = $icons.get(typeStr)) != null ? _ref1.get("faClass") : void 0;
          if (!faClass) {
            if (typeof console !== "undefined" && console !== null) {
              console.error("could not find icon for type: " + typeStr);
            }
            faClass = "fighter-jet";
          }
          return rowView.$el.find(".card__header-icon").addClass("fa-" + faClass);
        }
      }
    };
    viewRowDetail.DetailViewMixins.label = {
      html: function() {
        return false;
      },
      insertInDOM: function(rowView) {
        var cht;

        cht = rowView.$label;
        cht.html(this.model.get("value") || new Array(10).join('&nbsp;'));
        return this;
      }
    };
    viewRowDetail.DetailViewMixins.hint = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return viewRowDetail.Templates.textbox(this.cid, this.model.key, 'Question hint', 'text');
      },
      afterRender: function() {
        return this.listenForInputChange();
      }
    };
    viewRowDetail.DetailViewMixins.constraint_message = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return viewRowDetail.Templates.textbox(this.cid, this.model.key, 'Error Message', 'text');
      },
      insertInDOM: function(rowView) {
        return this._insertInDOM(rowView.cardSettingsWrap.find('.card__settings__fields--validation-criteria').eq(0));
      },
      afterRender: function() {
        return this.listenForInputChange();
      }
    };
    viewRowDetail.DetailViewMixins.relevant = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return "<div class=\"card__settings__fields__field relevant__editor\">\n</div>";
      },
      afterRender: function() {
        this.$el.find(".relevant__editor").html("<div class=\"skiplogic__main\"></div>\n<p class=\"skiplogic__extras\">\n</p>");
        this.target_element = this.$('.skiplogic__main');
        return this.model.facade.render(this.target_element);
      },
      insertInDOM: function(rowView) {
        return this._insertInDOM(rowView.cardSettingsWrap.find('.card__settings__fields--skip-logic').eq(0));
      }
    };
    viewRowDetail.DetailViewMixins.constraint = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return "<div class=\"card__settings__fields__field constraint__editor\">\n</div>";
      },
      afterRender: function() {
        this.$el.find(".constraint__editor").html("<div class=\"skiplogic__main\"></div>\n<p class=\"skiplogic__extras\">\n</p>");
        this.target_element = this.$('.skiplogic__main');
        return this.model.facade.render(this.target_element);
      },
      insertInDOM: function(rowView) {
        return this._insertInDOM(rowView.cardSettingsWrap.find('.card__settings__fields--validation-criteria'));
      }
    };
    viewRowDetail.DetailViewMixins.name = {
      html: function() {
        this.fieldTab = "active";
        this.$el.addClass("card__settings__fields--" + this.fieldTab);
        return viewRowDetail.Templates.textbox(this.cid, this.model.key, 'Data column name', 'text');
      },
      afterRender: function() {
        var update_view,
          _this = this;

        this.listenForInputChange({
          transformFn: function(value) {
            var value_chars;

            value_chars = value.split('');
            if (!/[\w_]/.test(value_chars[0])) {
              value_chars.unshift('_');
            }
            _this.model.set('value', value);
            return _this.model.deduplicate(_this.model.getSurvey());
          }
        });
        update_view = function() {
          return _this.$el.find('input').eq(0).val(_this.model.get("value") || $modelUtils.sluggifyLabel(_this.model._parent.getValue('label')));
        };
        update_view();
        return this.model._parent.get('label').on('change:value', update_view);
      }
    };
    viewRowDetail.DetailViewMixins["default"] = {
      html: function() {
        var label;

        this.fieldTab = "active";
        this.$el.addClass("card__settings__fields--" + this.fieldTab);
        label = this.model.key === 'default' ? 'Default response' : this.model.key.replace(/_/g, ' ');
        return viewRowDetail.Templates.textbox(this.cid, this.model.key, label, 'text');
      },
      afterRender: function() {
        this.$el.find('input').eq(0).val(this.model.get("value"));
        return this.listenForInputChange();
      }
    };
    viewRowDetail.DetailViewMixins.calculation = {
      html: function() {
        return false;
      },
      insertInDOM: function(rowView) {}
    };
    viewRowDetail.DetailViewMixins._isRepeat = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return viewRowDetail.Templates.checkbox(this.cid, this.model.key, 'Repeat', 'Repeat this group if necessary');
      },
      afterRender: function() {
        return this.listenForCheckboxChange();
      }
    };
    viewRowDetail.DetailViewMixins.required = {
      html: function() {
        this.$el.addClass("card__settings__fields--active");
        return viewRowDetail.Templates.checkbox(this.cid, this.model.key, 'Mandatory response');
      },
      afterRender: function() {
        return this.listenForCheckboxChange();
      }
    };
    viewRowDetail.DetailViewMixins.appearance = {
      getTypes: function() {
        var types;

        types = {
          text: ['multiline', 'numbers'],
          select_one: ['minimal', 'quick', 'horizontal-compact', 'horizontal', 'likert', 'compact', 'quickcompact', 'label', 'list-nolabel'],
          select_multiple: ['minimal', 'horizontal-compact', 'horizontal', 'compact', 'label', 'list-nolabel'],
          image: ['signature', 'draw', 'annotate'],
          date: ['month-year', 'year'],
          group: ['select', 'field-list', 'table-list', 'other']
        };
        return types[this.model._parent.getValue('type').split(' ')[0]];
      },
      html: function() {
        var appearances;

        this.$el.addClass("card__settings__fields--active");
        if (this.model_is_group(this.model)) {
          return viewRowDetail.Templates.checkbox(this.cid, this.model.key, 'Appearance (advanced)', 'Show all questions in this group on the same screen');
        } else {
          appearances = this.getTypes();
          if (appearances != null) {
            appearances.push('other');
            appearances.unshift('select');
            return viewRowDetail.Templates.dropdown(this.cid, this.model.key, appearances, 'Appearance (advanced)');
          } else {
            return viewRowDetail.Templates.textbox(this.cid, this.model.key, 'Appearance (advanced)', 'text');
          }
        }
      },
      model_is_group: function(model) {
        return model._parent.constructor.key === 'group';
      },
      afterRender: function() {
        var $input, $select, modelValue,
          _this = this;

        $select = this.$('select');
        modelValue = this.model.get('value');
        if ($select.length > 0) {
          $input = $('<input/>', {
            "class": 'text',
            type: 'text',
            width: 'auto'
          });
          if (modelValue !== '') {
            if ((this.getTypes() != null) && __indexOf.call(this.getTypes(), modelValue) >= 0) {
              $select.val(modelValue);
            } else {
              $select.val('other');
              this.$('.settings__input').append($input);
              this.listenForInputChange({
                el: $input
              });
            }
          }
          return $select.change(function() {
            if ($select.val() === 'other') {
              _this.model.set('value', '');
              _this.$('.settings__input').append($input);
              return _this.listenForInputChange({
                el: $input
              });
            } else if ($select.val() === 'select') {
              return _this.model.set('value', '');
            } else {
              _this.model.set('value', $select.val());
              return $input.remove();
            }
          });
        } else {
          $input = this.$('input');
          if ($input.attr('type') === 'text') {
            this.$('input[type=text]').val(modelValue);
            return this.listenForInputChange();
          } else if ($input.attr('type') === 'checkbox') {
            if (this.model.get('value') === 'field-list') {
              $input.prop('checked', true);
            }
            return $input.on('change', function() {
              if ($input.prop('checked')) {
                return _this.model.set('value', 'field-list');
              } else {
                return _this.model.set('value', '');
              }
            });
          }
        }
      }
    };
    return viewRowDetail;
  });

}).call(this);


(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __slice = [].slice;

  define('cs!xlform/view.row', ['backbone', 'jquery', 'cs!xlform/view.rowSelector', 'cs!xlform/model.row', 'cs!xlform/model.utils', 'cs!xlform/view.templates', 'cs!xlform/view.utils', 'cs!xlform/view.choices', 'cs!xlform/view.rowDetail'], function(Backbone, $, $rowSelector, $row, $modelUtils, $viewTemplates, $viewUtils, $viewChoices, $viewRowDetail) {
    var BaseRowView, GroupView, RankScoreView, RankView, RowView, ScoreView, _ref, _ref1, _ref2, _ref3, _ref4, _ref5;

    BaseRowView = (function(_super) {
      __extends(BaseRowView, _super);

      function BaseRowView() {
        this.add_row_to_question_library = __bind(this.add_row_to_question_library, this);
        this.clone = __bind(this.clone, this);        _ref = BaseRowView.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      BaseRowView.prototype.tagName = "li";

      BaseRowView.prototype.className = "survey__row  xlf-row-view xlf-row-view--depr";

      BaseRowView.prototype.events = {
        "drop": "drop"
      };

      BaseRowView.prototype.initialize = function(opts) {
        var typeDetail,
          _this = this;

        this.options = opts;
        typeDetail = this.model.get("type");
        this.$el.attr("data-row-id", this.model.cid);
        this.ngScope = opts.ngScope;
        this.surveyView = this.options.surveyView;
        return this.model.on("detail-change", function(key, value, ctxt) {
          var customEventName;

          customEventName = "row-detail-change-" + key;
          return _this.$(".on-" + customEventName).trigger(customEventName, key, value, ctxt);
        });
      };

      BaseRowView.prototype.drop = function(evt, index) {
        return this.$el.trigger("update-sort", [this.model, index]);
      };

      BaseRowView.prototype.getApp = function() {
        return this.surveyView.getApp();
      };

      BaseRowView.prototype.render = function(opts) {
        var fixScroll, _ref1;

        if (opts == null) {
          opts = {};
        }
        fixScroll = opts.fixScroll;
        if (this.already_rendered) {
          return;
        }
        if (fixScroll) {
          this.$el.height(this.$el.height());
        }
        this.already_rendered = true;
        if (this.model instanceof $row.RowError) {
          this._renderError();
        } else {
          this._renderRow();
        }
        this.is_expanded = (_ref1 = this.$card) != null ? _ref1.hasClass('card--expandedchoices') : void 0;
        if (fixScroll) {
          this.$el.attr('style', '');
        }
        return this;
      };

      BaseRowView.prototype._renderError = function() {
        var atts;

        this.$el.addClass("xlf-row-view-error");
        atts = $viewUtils.cleanStringify(this.model.toJSON());
        this.$el.html($viewTemplates.$$render('row.rowErrorView', atts));
        return this;
      };

      BaseRowView.prototype._renderRow = function() {
        var cl, context, key, val, view, _i, _len, _ref1, _ref2;

        this.$el.html($viewTemplates.$$render('row.xlfRowView', this.surveyView));
        this.$label = this.$('.card__header-title');
        this.$card = this.$('.card');
        this.$header = this.$('.card__header');
        context = {
          warnings: []
        };
        if ('getList' in this.model && (cl = this.model.getList())) {
          this.$card.addClass('card--selectquestion card--expandedchoices');
          this.is_expanded = true;
          this.listView = new $viewChoices.ListView({
            model: cl,
            rowView: this
          }).render();
        }
        this.cardSettingsWrap = this.$('.card__settings').eq(0);
        this.defaultRowDetailParent = this.cardSettingsWrap.find('.card__settings__fields--question-options').eq(0);
        _ref1 = this.model.attributesArray();
        for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
          _ref2 = _ref1[_i], key = _ref2[0], val = _ref2[1];
          if (!(key === 'label' || key === 'type')) {
            continue;
          }
          view = new $viewRowDetail.DetailView({
            model: val,
            rowView: this
          });
          if (key === 'label' && this.model.get('type').get('value') === 'calculate') {
            view.model = this.model.get('calculation');
            this.model.finalize();
            val.set('value', '');
          }
          view.render().insertInDOM(this);
          if (key === 'label') {
            this.make_label_editable(view);
          }
        }
        return this;
      };

      BaseRowView.prototype.toggleSettings = function(show) {
        if (show === void 0) {
          show = !this._settingsExpanded;
        }
        if (show && !this._settingsExpanded) {
          this._expandedRender();
          this.$card.addClass('card--expanded-settings');
          if (typeof this.hideMultioptions === "function") {
            this.hideMultioptions();
          }
          this._settingsExpanded = true;
        } else if (!show && this._settingsExpanded) {
          this.$card.removeClass('card--expanded-settings');
          this._cleanupExpandedRender();
          this._settingsExpanded = false;
        }
        return ;
      };

      BaseRowView.prototype._cleanupExpandedRender = function() {
        return this.$('.card__settings').detach();
      };

      BaseRowView.prototype.clone = function(event) {
        var model, parent, _ref1, _ref2;

        parent = this.model._parent;
        model = this.model;
        if ((_ref1 = this.model.get('type').get('typeId')) === 'select_one' || _ref1 === 'select_multiple') {
          model = this.model.clone();
        } else if ((_ref2 = this.model.get('type').get('typeId')) === 'rank' || _ref2 === 'score') {
          model = this.model.clone();
        }
        return this.model.getSurvey().insert_row.call(parent._parent, model, parent.models.indexOf(this.model) + 1);
      };

      BaseRowView.prototype.add_row_to_question_library = function(evt) {
        var _ref1;

        evt.stopPropagation();
        return (_ref1 = this.ngScope) != null ? _ref1.add_row_to_question_library(this.model) : void 0;
      };

      return BaseRowView;

    })(Backbone.View);
    GroupView = (function(_super) {
      __extends(GroupView, _super);

      function GroupView() {
        this._deleteGroup = __bind(this._deleteGroup, this);
        this.deleteGroup = __bind(this.deleteGroup, this);        _ref1 = GroupView.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      GroupView.prototype.className = "survey__row survey__row--group  xlf-row-view xlf-row-view--depr";

      GroupView.prototype.initialize = function(opts) {
        this.options = opts;
        this._shrunk = !!opts.shrunk;
        this.$el.attr("data-row-id", this.model.cid);
        return this.surveyView = this.options.surveyView;
      };

      GroupView.prototype.deleteGroup = function(evt) {
        var skipConfirm;

        skipConfirm = $(evt.currentTarget).hasClass('js-force-delete-group');
        if (skipConfirm || confirm('Are you sure you want to split apart this group?')) {
          this._deleteGroup();
        }
        return evt.preventDefault();
      };

      GroupView.prototype._deleteGroup = function() {
        this.model.splitApart();
        this.model._parent._parent.trigger('remove', this.model);
        return this.$el.detach();
      };

      GroupView.prototype.render = function() {
        var _this = this;

        if (!this.already_rendered) {
          this.$el.html($viewTemplates.row.groupView(this.model));
          this.$label = this.$('.group__label').eq(0);
          this.$rows = this.$('.group__rows').eq(0);
          this.$card = this.$('.card');
          this.$header = this.$('.card__header,.group__header').eq(0);
        }
        this.model.rows.each(function(row) {
          return _this.getApp().ensureElInView(row, _this, _this.$rows).render();
        });
        if (!this.already_rendered) {
          this.make_label_editable(new $viewRowDetail.DetailView({
            model: this.model.get('label'),
            rowView: this
          }).render().insertInDOM(this));
        }
        this.already_rendered = true;
        return this;
      };

      GroupView.prototype.hasNestedGroups = function() {
        return _.filter(this.model.rows.models, function(row) {
          return row.constructor.key === 'group';
        }).length > 0;
      };

      GroupView.prototype._expandedRender = function() {
        var key, val, _i, _len, _ref2, _ref3,
          _this = this;

        this.$header.after($viewTemplates.row.groupSettingsView());
        this.cardSettingsWrap = this.$('.card__settings').eq(0);
        this.defaultRowDetailParent = this.cardSettingsWrap.find('.card__settings__fields--active').eq(0);
        _ref2 = this.model.attributesArray();
        for (_i = 0, _len = _ref2.length; _i < _len; _i++) {
          _ref3 = _ref2[_i], key = _ref3[0], val = _ref3[1];
          if (key === "name" || key === "_isRepeat" || key === "appearance" || key === "relevant") {
            new $viewRowDetail.DetailView({
              model: val,
              rowView: this
            }).render().insertInDOM(this);
          }
        }
        if (this.hasNestedGroups()) {
          this.$('.xlf-dv-appearance').hide();
        }
        this.model.on('add', function(row) {
          var $appearanceField, appearanceModel;

          if (row.constructor.key === 'group') {
            $appearanceField = _this.$('.xlf-dv-appearance').eq(0);
            $appearanceField.hide();
            $appearanceField.find('input:checkbox').prop('checked', false);
            appearanceModel = _this.model.get('appearance');
            if (appearanceModel.getValue()) {
              _this.surveyView.ngScope.miscUtils.alert("You can't display nested groups on the same screen - the setting has been removed from the parent group");
            }
            return appearanceModel.set('value', '');
          }
        });
        this.model.on('remove', function(row) {
          if (row.constructor.key === 'group' && !_this.hasNestedGroups()) {
            return _this.$('.xlf-dv-appearance').eq(0).show();
          }
        });
        return this;
      };

      GroupView.prototype.make_label_editable = function(view) {
        return $viewUtils.makeEditable(view, view.model, this.$label, {
          options: {
            placement: 'right',
            rows: 3
          },
          edit_callback: function(value) {
            value = value.replace(new RegExp(String.fromCharCode(160), 'g'), '');
            value = value.replace(/\t/g, ' ');
            view.model.set('value', value);
            if (value === '') {
              return {
                newValue: new Array(10).join('&nbsp;')
              };
            } else {

            }
            return {
              newValue: value
            };
          }
        });
      };

      return GroupView;

    })(BaseRowView);
    RowView = (function(_super) {
      __extends(RowView, _super);

      function RowView() {
        _ref2 = RowView.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      RowView.prototype._expandedRender = function() {
        var key, val, _i, _len, _ref3, _ref4;

        this.$header.after($viewTemplates.row.rowSettingsView());
        this.cardSettingsWrap = this.$('.card__settings').eq(0);
        this.defaultRowDetailParent = this.cardSettingsWrap.find('.card__settings__fields--question-options').eq(0);
        _ref3 = this.model.attributesArray();
        for (_i = 0, _len = _ref3.length; _i < _len; _i++) {
          _ref4 = _ref3[_i], key = _ref4[0], val = _ref4[1];
          if (key !== "label" && key !== "type") {
            new $viewRowDetail.DetailView({
              model: val,
              rowView: this
            }).render().insertInDOM(this);
          }
        }
        return this;
      };

      RowView.prototype.hideMultioptions = function() {
        this.$card.removeClass('card--expandedchoices');
        return this.is_expanded = false;
      };

      RowView.prototype.showMultioptions = function() {
        this.$card.addClass('card--expandedchoices');
        this.$card.removeClass('card--expanded-settings');
        return this.toggleSettings(false);
      };

      RowView.prototype.toggleMultioptions = function() {
        if (this.is_expanded) {
          this.hideMultioptions();
        } else {
          this.showMultioptions();
          this.is_expanded = true;
        }
      };

      RowView.prototype.make_label_editable = function(view) {
        return $viewUtils.makeEditable(view, view.model, this.$label, {
          options: {
            placement: 'right',
            rows: 3
          },
          transformFunction: function(value) {
            return value;
          }
        });
      };

      return RowView;

    })(BaseRowView);
    RankScoreView = (function(_super) {
      __extends(RankScoreView, _super);

      function RankScoreView() {
        _ref3 = RankScoreView.__super__.constructor.apply(this, arguments);
        return _ref3;
      }

      RankScoreView.prototype._expandedRender = function() {
        RankScoreView.__super__._expandedRender.call(this);
        this.$('.xlf-dv-required').hide();
        return this.$("li[data-card-settings-tab-id='validation-criteria']").hide();
      };

      return RankScoreView;

    })(RowView);
    ScoreView = (function(_super) {
      __extends(ScoreView, _super);

      function ScoreView() {
        _ref4 = ScoreView.__super__.constructor.apply(this, arguments);
        return _ref4;
      }

      ScoreView.prototype.className = "survey__row survey__row--score";

      ScoreView.prototype._renderRow = function() {
        var $choices, $el, $rows, args, autoname, beta_elem, extra_score_contents, get_choice, get_row, offOn, sc, score_choices, score_rows, sr, template_args,
          _this = this;

        args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
        ScoreView.__super__._renderRow.call(this, args);
        beta_elem = $('<p>', {
          "class": 'scorerank-beta-warning',
          text: 'Note: Rank and Matrix question types are currently in beta.'
        });
        while (this.model._scoreChoices.options.length < 2) {
          this.model._scoreChoices.options.add({
            label: 'Option'
          });
        }
        score_choices = (function() {
          var _i, _len, _ref5, _ref6, _results;

          _ref5 = this.model._scoreChoices.options.models;
          _results = [];
          for (_i = 0, _len = _ref5.length; _i < _len; _i++) {
            sc = _ref5[_i];
            autoname = '';
            if ((_ref6 = sc.get('name')) === (void 0) || _ref6 === '') {
              autoname = $modelUtils.sluggify(sc.get('label'));
            }
            _results.push({
              label: sc.get('label'),
              name: sc.get('name'),
              autoname: autoname,
              cid: sc.cid
            });
          }
          return _results;
        }).call(this);
        if (this.model._scoreRows.length < 1) {
          this.model._scoreRows.add({
            label: 'Enter your question',
            name: ''
          });
        }
        score_rows = (function() {
          var _i, _len, _ref5, _ref6, _results;

          _ref5 = this.model._scoreRows.models;
          _results = [];
          for (_i = 0, _len = _ref5.length; _i < _len; _i++) {
            sr = _ref5[_i];
            if ((_ref6 = sr.get('name')) === (void 0) || _ref6 === '') {
              autoname = $modelUtils.sluggify(sr.get('label'), {
                validXmlTag: true
              });
            } else {
              autoname = '';
            }
            _results.push({
              label: sr.get('label'),
              name: sr.get('name'),
              autoname: autoname,
              cid: sr.cid
            });
          }
          return _results;
        }).call(this);
        template_args = {
          score_rows: score_rows,
          score_choices: score_choices
        };
        extra_score_contents = $viewTemplates.$$render('row.scoreView', template_args);
        this.$('.card--selectquestion__expansion').eq(0).append(extra_score_contents).addClass('js-cancel-select-row');
        this.$('.card').eq(0).append(beta_elem);
        $rows = this.$('.score__contents--rows').eq(0);
        $choices = this.$('.score__contents--choices').eq(0);
        $el = this.$el;
        offOn = function(evtName, selector, callback) {
          return $el.off(evtName).on(evtName, selector, callback);
        };
        get_row = function(cid) {
          return _this.model._scoreRows.get(cid);
        };
        get_choice = function(cid) {
          return _this.model._scoreChoices.options.get(cid);
        };
        offOn('click.deletescorerow', '.js-delete-scorerow', function(evt) {
          var $et, row_cid;

          $et = $(evt.target);
          row_cid = $et.closest('tr').eq(0).data('row-cid');
          _this.model._scoreRows.remove(get_row(row_cid));
          _this.already_rendered = false;
          return _this.render({
            fixScroll: true
          });
        });
        offOn('click.deletescorecol', '.js-delete-scorecol', function(evt) {
          var $et;

          log('here');
          $et = $(evt.target);
          _this.model._scoreChoices.options.remove(get_choice($et.closest('th').data('cid')));
          _this.already_rendered = false;
          return _this.render({
            fixScroll: true
          });
        });
        offOn('input.editscorelabel', '.scorelabel__edit', function(evt) {
          var $et, row_cid;

          $et = $(evt.target);
          row_cid = $et.closest('tr').eq(0).data('row-cid');
          return get_row(row_cid).set('label', $et.text());
        });
        offOn('input.namechange', '.scorelabel__name', function(evt) {
          var $ect, row_cid, _inpText, _text;

          $ect = $(evt.currentTarget);
          row_cid = $ect.closest('tr').eq(0).data('row-cid');
          _inpText = $ect.text();
          _text = $modelUtils.sluggify(_inpText, {
            validXmlTag: true
          });
          get_row(row_cid).set('name', _text);
          if (_text === '') {
            $ect.addClass('scorelabel__name--automatic');
          } else {
            $ect.removeClass('scorelabel__name--automatic');
          }
          $ect.off('blur');
          return $ect.on('blur', function() {
            if (_inpText !== _text) {
              $ect.text(_text);
            }
            if (_text === '') {
              $ect.addClass('scorelabel__name--automatic');
              return $ect.closest('td').find('.scorelabel__edit').trigger('keyup');
            } else {
              return $ect.removeClass('scorelabel__name--automatic');
            }
          });
        });
        offOn('keyup.namekey', '.scorelabel__edit', function(evt) {
          var $ect, $nameWrap;

          $ect = $(evt.currentTarget);
          $nameWrap = $ect.closest('.scorelabel').find('.scorelabel__name');
          log($nameWrap);
          return $nameWrap.attr('data-automatic-name', $modelUtils.sluggify($ect.text(), {
            validXmlTag: true
          }));
        });
        offOn('input.choicechange', '.scorecell__label', function(evt) {
          var $et;

          $et = $(evt.target);
          return get_choice($et.closest('th').data('cid')).set('label', $et.text());
        });
        offOn('input.optvalchange', '.scorecell__name', function(evt) {
          var $et, _text;

          $et = $(evt.target);
          _text = $et.text();
          if (_text === '') {
            $et.addClass('scorecell__name--automatic');
          } else {
            $et.removeClass('scorecell__name--automatic');
          }
          return get_choice($et.closest('th').eq(0).data('cid')).set('name', _text);
        });
        offOn('keyup.optlabelchange', '.scorecell__label', function(evt) {
          var $ect, $nameWrap;

          $ect = $(evt.currentTarget);
          $nameWrap = $ect.closest('.scorecell__col').find('.scorecell__name');
          return $nameWrap.attr('data-automatic-name', $modelUtils.sluggify($ect.text()));
        });
        offOn('blur.choicechange', '.scorecell__label', function(evt) {
          return _this.render();
        });
        offOn('click.addchoice', '.scorecell--add', function(evt) {
          _this.already_rendered = false;
          _this.model._scoreChoices.options.add([
            {
              label: 'Option'
            }
          ]);
          return _this.render({
            fixScroll: true
          });
        });
        return offOn('click.addrow', '.scorerow--add', function(evt) {
          _this.already_rendered = false;
          _this.model._scoreRows.add([
            {
              label: 'Enter your question'
            }
          ]);
          return _this.render({
            fixScroll: true
          });
        });
      };

      return ScoreView;

    })(RankScoreView);
    RankView = (function(_super) {
      __extends(RankView, _super);

      function RankView() {
        _ref5 = RankView.__super__.constructor.apply(this, arguments);
        return _ref5;
      }

      RankView.prototype.className = "survey__row survey__row--rank";

      RankView.prototype._renderRow = function() {
        var args, beta_elem, extra_score_contents, min_rank_levels_count, model, rank_levels, rank_rows, template_args, _automatic, _label, _name, _ref6;

        args = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
        RankView.__super__._renderRow.call(this, args);
        beta_elem = $('<p>', {
          "class": 'scorerank-beta-warning',
          text: 'Note: Rank and Matrix question types are currently in beta.'
        });
        template_args = {};
        template_args.rank_constraint_msg = (_ref6 = this.model.get('kobo--rank-constraint-message')) != null ? _ref6.get('value') : void 0;
        min_rank_levels_count = 2;
        if (this.model._rankRows.length > min_rank_levels_count) {
          min_rank_levels_count = this.model._rankRows.length;
        }
        while (this.model._rankLevels.options.length < min_rank_levels_count) {
          this.model._rankLevels.options.add({
            label: "Item to be ranked",
            name: ''
          });
        }
        rank_levels = (function() {
          var _i, _len, _ref7, _results;

          _ref7 = this.model._rankLevels.options.models;
          _results = [];
          for (_i = 0, _len = _ref7.length; _i < _len; _i++) {
            model = _ref7[_i];
            _label = model.get('label');
            _name = model.get('name');
            _automatic = $modelUtils.sluggify(_label);
            _results.push({
              label: _label,
              name: _name,
              automatic: _automatic,
              set_automatic: _name === '',
              cid: model.cid
            });
          }
          return _results;
        }).call(this);
        template_args.rank_levels = rank_levels;
        while (this.model._rankRows.length < 1) {
          this.model._rankRows.add({
            label: '1st choice',
            name: ''
          });
        }
        rank_rows = (function() {
          var _i, _len, _ref7, _results;

          _ref7 = this.model._rankRows.models;
          _results = [];
          for (_i = 0, _len = _ref7.length; _i < _len; _i++) {
            model = _ref7[_i];
            _label = model.get('label');
            _name = model.get('name');
            _automatic = $modelUtils.sluggify(_label, {
              validXmlTag: true
            });
            _results.push({
              label: _label,
              name: _name,
              automatic: _automatic,
              set_automatic: _name === '',
              cid: model.cid
            });
          }
          return _results;
        }).call(this);
        template_args.rank_rows = rank_rows;
        extra_score_contents = $viewTemplates.$$render('row.rankView', this, template_args);
        this.$('.card').append(beta_elem);
        this.$('.card--selectquestion__expansion').eq(0).append(extra_score_contents).addClass('js-cancel-select-row');
        return this.editRanks();
      };

      RankView.prototype.editRanks = function() {
        var $el, get_item, offOn,
          _this = this;

        this.$(['.rank_items__item__label', '.rank_items__level__label', '.rank_items__constraint_message', '.rank_items__name'].join(',')).attr('contenteditable', 'true');
        $el = this.$el;
        offOn = function(evtName, selector, callback) {
          return $el.off(evtName).on(evtName, selector, callback);
        };
        get_item = function(evt) {
          var cid, parli;

          parli = $(evt.target).parents('li').eq(0);
          cid = parli.eq(0).data('cid');
          if (parli.hasClass('rank_items__level')) {
            return _this.model._rankLevels.options.get(cid);
          } else {
            return _this.model._rankRows.get(cid);
          }
        };
        offOn('click.deleterankcell', '.js-delete-rankcell', function(evt) {
          var collection, item;

          if ($(evt.target).parents('.rank__rows').length === 0) {
            collection = _this.model._rankLevels.options;
          } else {
            collection = _this.model._rankRows;
          }
          item = get_item(evt);
          collection.remove(item);
          _this.already_rendered = false;
          return _this.render({
            fixScroll: true
          });
        });
        offOn('input.ranklabelchange1', '.rank_items__item__label', function(evt) {
          var $ect, $riName, _slugtext, _text;

          $ect = $(evt.currentTarget);
          _text = $ect.text();
          _slugtext = $modelUtils.sluggify(_text, {
            validXmlTag: true
          });
          $riName = $ect.closest('.rank_items__item').find('.rank_items__name');
          $riName.attr('data-automatic-name', _slugtext);
          return get_item(evt).set('label', _text);
        });
        offOn('input.ranklabelchange2', '.rank_items__level__label', function(evt) {
          var $ect, $riName, _slugtext, _text;

          $ect = $(evt.currentTarget);
          _text = $ect.text();
          _slugtext = $modelUtils.sluggify(_text);
          $riName = $ect.closest('.rank_items__level').find('.rank_items__name');
          $riName.attr('data-automatic-name', _slugtext);
          return get_item(evt).set('label', _text);
        });
        offOn('input.ranklabelchange3', '.rank_items__name', function(evt) {
          var $ect, needs_valid_xml, _inptext, _text;

          $ect = $(evt.currentTarget);
          _inptext = $ect.text();
          needs_valid_xml = $ect.parents('.rank_items__item').length > 0;
          _text = $modelUtils.sluggify(_inptext, {
            validXmlTag: needs_valid_xml
          });
          $ect.off('blur');
          $ect.one('blur', function() {
            if (_text === '') {
              return $ect.addClass('rank_items__name--automatic');
            } else {
              if (_inptext !== _text) {
                log('changin');
                $ect.text(_text);
              }
              return $ect.removeClass('rank_items__name--automatic');
            }
          });
          return get_item(evt).set('name', _text);
        });
        offOn('focus', '.rank_items__constraint_message--prelim', function(evt) {
          return $(evt.target).removeClass('rank_items__constraint_message--prelim').empty();
        });
        offOn('input.ranklabelchange4', '.rank_items__constraint_message', function(evt) {
          var rnkKey;

          rnkKey = 'kobo--rank-constraint-message';
          return _this.model.get(rnkKey).set('value', evt.target.textContent);
        });
        return offOn('click.addrow', '.rank_items__add', function(evt) {
          var ch, chz;

          if ($(evt.target).parents('.rank__rows').length === 0) {
            _this.model._rankLevels.options.add({
              label: 'Item',
              name: ''
            });
          } else {
            chz = "1st 2nd 3rd".split(' ');
            ch = _this.model._rankRows.length + 1 > chz.length ? "" + (_this.model._rankRows.length + 1) + "th" : chz[_this.model._rankRows.length];
            _this.model._rankRows.add({
              label: "" + ch + " choice",
              name: ''
            });
          }
          _this.already_rendered = false;
          return _this.render({
            fixScroll: true
          });
        });
      };

      return RankView;

    })(RankScoreView);
    return {
      RowView: RowView,
      ScoreView: ScoreView,
      GroupView: GroupView,
      RankView: RankView
    };
  });

}).call(this);


(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  define('cs!xlform/view.surveyApp', ['underscore', 'backbone', 'cs!xlform/model.survey', 'cs!xlform/model.utils', 'cs!xlform/view.templates', 'cs!xlform/view.surveyDetails', 'cs!xlform/view.rowSelector', 'cs!xlform/view.row', 'cs!xlform/view.pluggedIn.backboneView', 'cs!xlform/view.utils'], function(_, Backbone, $survey, $modelUtils, $viewTemplates, $surveyDetailView, $viewRowSelector, $rowView, $baseView, $viewUtils) {
    var SurveyFragmentApp, surveyApp, _notifyIfRowsOutOfOrder, _ref, _ref1, _ref2, _ref3;

    surveyApp = {};
    _notifyIfRowsOutOfOrder = (function() {
      var fn;

      fn = function(surveyApp) {
        var elIds, gatherId, rIds, survey, _s;

        survey = surveyApp.survey;
        elIds = [];
        surveyApp.$('.survey__row').each(function() {
          return elIds.push($(this).data('rowId'));
        });
        rIds = [];
        gatherId = function(r) {
          return rIds.push(r.cid);
        };
        survey.forEachRow(gatherId, {
          includeGroups: true
        });
        _s = function(i) {
          return JSON.stringify(i);
        };
        if (_s(rIds) !== _s(elIds)) {
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.log(_s(rIds));
          }
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.log(_s(elIds));
          }
          if (typeof trackJs !== "undefined" && trackJs !== null) {
            trackJs.console.error("Row model does not match view");
          }
          return false;
        } else {
          return true;
        }
      };
      return _.debounce(fn, 2500);
    })();
    SurveyFragmentApp = (function(_super) {
      __extends(SurveyFragmentApp, _super);

      function SurveyFragmentApp() {
        this.deselect_rows = __bind(this.deselect_rows, this);        _ref = SurveyFragmentApp.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      SurveyFragmentApp.prototype.className = "formbuilder-wrap container";

      SurveyFragmentApp.prototype.features = {};

      SurveyFragmentApp.prototype.events = {
        "click .js-delete-row": "clickRemoveRow",
        "click .js-delete-group": "clickDeleteGroup",
        "click .js-add-to-question-library": "clickAddRowToQuestionLibrary",
        "click .js-clone-question": "clickCloneQuestion",
        "click #xlf-preview": "previewButtonClick",
        "click #csv-preview": "previewCsv",
        "click #xlf-download": "downloadButtonClick",
        "click #save": "saveButtonClick",
        "click #publish": "publishButtonClick",
        "click #settings": "toggleSurveySettings",
        "update-sort": "updateSort",
        "click .js-select-row": "selectRow",
        "click .js-select-row--force": "forceSelectRow",
        "click .js-group-rows": "groupSelectedRows",
        "click .js-toggle-card-settings": "toggleCardSettings",
        "click .js-toggle-group-expansion": "toggleGroupExpansion",
        "click .js-toggle-row-multioptions": "toggleRowMultioptions",
        "click .js-close-warning": "closeWarningBox",
        "click .js-expand-row-selector": "expandRowSelector",
        "click .js-expand-multioptions--all": "expandMultioptions",
        "click .rowselector_toggle-library": "toggleLibrary",
        "mouseenter .card__buttons__button": "buttonHoverIn",
        "mouseleave .card__buttons__button": "buttonHoverOut",
        "click .card__settings__tabs li": "switchTab"
      };

      SurveyFragmentApp.create = function(params) {
        if (params == null) {
          params = {};
        }
        if (_.isString(params.el)) {
          params.el = $(params.el).get(0);
        }
        return new this(params);
      };

      SurveyFragmentApp.prototype.switchTab = function(event) {
        var $et, tabId;

        $et = $(event.currentTarget);
        if ($et.hasClass("heading")) {
          event.preventDefault();
          return;
        }
        tabId = $et.data('cardSettingsTabId');
        $et.parent('ul').find('.card__settings__tabs__tab--active').removeClass('card__settings__tabs__tab--active');
        $et.addClass('card__settings__tabs__tab--active');
        $et.parents('.card__settings').find(".card__settings__fields--active").removeClass('card__settings__fields--active');
        return $et.parents('.card__settings').find(".card__settings__fields--" + tabId).addClass('card__settings__fields--active');
      };

      SurveyFragmentApp.prototype.surveyRowSortableStop = function(evt) {
        var $et, cid, row, survey_findRowByCid, _par, _prev, _ref1,
          _this = this;

        $et = $(evt.target);
        cid = $et.data('rowId');
        survey_findRowByCid = function(cid) {
          if (cid) {
            return _this.survey.findRowByCid(cid, {
              includeGroups: true
            });
          }
        };
        row = survey_findRowByCid(cid);
        _ref1 = this._getRelatedElIds($et), _prev = _ref1[0], _par = _ref1[1];
        this.survey._insertRowInPlace(row, {
          previous: survey_findRowByCid(_prev),
          parent: survey_findRowByCid(_par),
          event: 'sort'
        });
      };

      SurveyFragmentApp.prototype._getRelatedElIds = function($el) {
        var parent, prev;

        prev = $el.prev('.survey__row').eq(0).data('rowId');
        parent = $el.parents('.survey__row').eq(0).data('rowId');
        return [prev, parent];
      };

      SurveyFragmentApp.prototype.initialize = function(options) {
        var _this = this;

        this.reset = function() {
          var promise;

          if (_this._timedReset) {
            clearTimeout(_this._timedReset);
          }
          promise = $.Deferred();
          _this._timedReset = setTimeout(function() {
            _this._reset.call(_this);
            return promise.resolve();
          }, 0);
          return promise;
        };
        if (options.survey && (options.survey instanceof $survey.Survey)) {
          this.survey = options.survey;
        } else {
          this.survey = new $survey.Survey(options);
        }
        this.warnings = options.warnings || [];
        this.__rowViews = new Backbone.Model();
        this.ngScope = options.ngScope;
        $(document).on('click', this.deselect_rows);
        this.survey.settings.on('change:form_id', function(model, value) {
          return $('.form-id').text(value);
        });
        this.survey.on('rows-add', this.reset, this);
        this.survey.on('rows-remove', this.reset, this);
        this.survey.on("row-detail-change", function(row, key, val, ctxt) {
          var evtCode;

          evtCode = "row-detail-change-" + key;
          return _this.$(".on-" + evtCode).trigger(evtCode, row, key, val, ctxt);
        });
        this.$el.on("choice-list-update", function(evt, clId) {
          $(".on-choice-list-update[data-choice-list-cid='" + clId + "']").trigger("rebuild-choice-list");
          return _this.survey.trigger('choice-list-update', clId);
        });
        this.$el.on("survey__row-sortablestop", _.bind(this.surveyRowSortableStop, this));
        this.onPublish = options.publish || $.noop;
        this.onSave = options.save || $.noop;
        this.onPreview = options.preview || $.noop;
        this.expand_all_multioptions = function() {
          return this.$('.survey__row:not(.survey__row--deleted) .card--expandedchoices:visible').length > 0;
        };
        return $(window).on("keydown", function(evt) {
          if (evt.keyCode === 27) {
            return _this.onEscapeKeydown(evt);
          }
        });
      };

      SurveyFragmentApp.prototype.getView = function(cid) {
        return this.__rowViews.get(cid);
      };

      SurveyFragmentApp.prototype.updateSort = function(evt, model, position) {
        this.survey.rows.remove(model);
        this.survey.rows.each(function(m, index) {
          return m.ordinal = index >= position ? index + 1 : index;
        });
        model.ordinal = position;
        this.survey.rows.add(model, {
          at: position
        });
      };

      SurveyFragmentApp.prototype.forceSelectRow = function(evt) {
        return this.selectRow($.extend({}, evt));
      };

      SurveyFragmentApp.prototype.deselect_all_rows = function() {
        return this.$('.survey__row').removeClass('survey__row--selected');
      };

      SurveyFragmentApp.prototype.deselect_rows = function(evt) {
        if (this.is_selecting) {
          this.is_selecting = false;
        } else {
          this.deselect_all_rows();
        }
      };

      SurveyFragmentApp.prototype.selectRow = function(evt) {
        var $ect, $et, $group, $target, selected_rows, _isIntendedTarget;

        this.is_selecting = true;
        $et = $(evt.target);
        if ($et.hasClass('js-blur-on-select-row') || $et.hasClass('editable-wrapper')) {
          return;
        }
        $ect = $(evt.currentTarget);
        if ($et.closest('.card__settings, .card__buttons, .group__header__buttons, .js-cancel-select-row').length > 0) {
          return;
        }
        _isIntendedTarget = $ect.closest('.survey__row').get(0) === $et.closest('.survey__row').get(0);
        if (_isIntendedTarget) {
          $target = $et.closest('.survey__row');
          if (!(evt.ctrlKey || evt.metaKey)) {
            selected_rows = $target.siblings('.survey__row--selected');
            if (!$target.hasClass('survey__row--selected') || selected_rows.length > 1) {
              this.deselect_all_rows();
            }
          }
          $target.toggleClass("survey__row--selected");
          if ($target.hasClass('survey__row--group')) {
            $target.find('li.survey__row, li.survey__row--group').toggleClass("survey__row--selected", $target.hasClass("survey__row--selected"));
          }
          $group = $target.parent().closest('.survey__row');
          if ($group.length > 0) {
            this.select_group_if_all_items_selected($group);
          }
          this.questionSelect();
          this.$('.js-blur-on-select-row').blur();
        }
      };

      SurveyFragmentApp.prototype.select_group_if_all_items_selected = function($group) {
        var $rows;

        $rows = $group.find('.survey__row');
        $group.toggleClass('survey__row--selected', $rows.length === $rows.filter('.survey__row--selected').length);
        $group = $group.parent().closest('.survey__row');
        if ($group.length > 0) {
          return this.select_group_if_all_items_selected($group);
        }
      };

      SurveyFragmentApp.prototype.questionSelect = function(evt) {
        this.activateGroupButton(this.$el.find('.survey__row--selected').length > 0);
      };

      SurveyFragmentApp.prototype.activateGroupButton = function(active) {
        if (active == null) {
          active = true;
        }
        return this.$('.btn--group-questions').toggleClass('btn--disabled', !active);
      };

      SurveyFragmentApp.prototype.getApp = function() {
        return this;
      };

      SurveyFragmentApp.prototype.toggleSurveySettings = function(evt) {
        var $et, $settings, close_settings;

        $et = $(evt.currentTarget);
        $et.toggleClass('active__settings');
        if (this.features.surveySettings) {
          $settings = this.$(".form__settings");
          $settings.toggle();
          close_settings = function(e) {
            var $settings_toggle, is_in_settings, is_in_settings_toggle;

            $settings_toggle = $('#settings');
            is_in_settings = function(element) {
              return element === $settings[0] || $settings.find(element).length > 0;
            };
            is_in_settings_toggle = function(element) {
              return element === $settings_toggle[0] || $settings_toggle.find(element).length > 0;
            };
            if (!(is_in_settings(e.target) || is_in_settings_toggle(e.target))) {
              $settings.hide();
              $et.removeClass('active__settings');
              return $('body').off('click', close_settings);
            }
          };
          return $('body').on('click', close_settings);
        }
      };

      SurveyFragmentApp.prototype._getViewForTarget = function(evt) {
        var $et, modelId, view;

        $et = $(evt.currentTarget);
        modelId = $et.closest('.survey__row').data('row-id');
        view = this.__rowViews.get(modelId);
        if (!view) {
          throw new Error("view is not found for target element");
        }
        return view;
      };

      SurveyFragmentApp.prototype.toggleCardSettings = function(evt) {
        return this._getViewForTarget(evt).toggleSettings();
      };

      SurveyFragmentApp.prototype.toggleGroupExpansion = function(evt) {
        var view;

        view = this._getViewForTarget(evt);
        return view.$el.toggleClass('group--shrunk');
      };

      SurveyFragmentApp.prototype.toggleRowMultioptions = function(evt) {
        var view;

        view = this._getViewForTarget(evt);
        view.toggleMultioptions();
        return this.set_multioptions_label();
      };

      SurveyFragmentApp.prototype.expandRowSelector = function(evt) {
        var $ect, $row, $spacer, rowId, view;

        $ect = $(evt.currentTarget);
        if ($ect.parents('.survey-editor__null-top-row').length > 0) {
          return this.null_top_row_view_selector.expand();
        } else {
          $row = $ect.parents('.survey__row').eq(0);
          $spacer = $ect.parents('.survey__row__spacer');
          rowId = $row.data('rowId');
          view = this.getViewForRow({
            cid: rowId
          });
          if (!view) {
            throw new Error('View for row was not found: ' + rowId);
          }
          return new $viewRowSelector.RowSelector({
            el: $spacer.get(0),
            ngScope: this.ngScope,
            spawnedFromView: view,
            surveyView: this,
            reversible: true,
            survey: this.survey
          }).expand();
        }
      };

      SurveyFragmentApp.prototype._render_html = function() {
        var _inp, _style_val;

        this.$el.html($viewTemplates.$$render('surveyApp', this));
        this.$settings = {
          form_id: this.$('.form__settings__field--form_id'),
          version: this.$('.form__settings__field--version'),
          style: this.$('.form__settings__field--style')
        };
        this.$settings.form_id.find('input').val(this.survey.settings.get('form_id'));
        this.$settings.version.find('input').val(this.survey.settings.get('version'));
        _style_val = this.survey.settings.get('style') || "";
        if (this.$settings.style.find('select option').filter((function(i, opt) {
          return opt.value === _style_val;
        })).length === 0) {
          _inp = $("<input>", {
            type: 'text'
          });
          this.$settings.style.find('select').replaceWith(_inp);
          _inp.val(_style_val);
        } else {
          this.$settings.style.find('select').val(_style_val);
        }
        this.formEditorEl = this.$(".-form-editor");
        return this.settingsBox = this.$(".form__settings-meta__questions");
      };

      SurveyFragmentApp.prototype._render_attachEvents = function() {
        var $inps, _settings;

        this.survey.settings.on('validated:invalid', function(model, validations) {
          var key, value, _results;

          _results = [];
          for (key in validations) {
            value = validations[key];
            break;
          }
          return _results;
        });
        if (this.features.displayTitle) {
          $viewUtils.makeEditable(this, this.survey.settings, '.form-title', {
            property: 'form_title',
            options: {
              validate: function(value) {
                if (value.length > 255) {
                  return "Length cannot exceed 255 characters, is " + value.length + " characters.";
                }
              }
            }
          });
        }
        $inps = {};
        _settings = this.survey.settings;
        if (this.$settings.form_id.length > 0) {
          $inps.form_id = this.$settings.form_id.find('input').eq(0);
          $inps.form_id.change(function(evt) {
            var _sluggified, _val;

            _val = $inps.form_id.val();
            _sluggified = $modelUtils.sluggify(_val);
            _settings.set('form_id', _sluggified);
            if (_sluggified !== _val) {
              return $inps.form_id.val(_sluggified);
            }
          });
        }
        if (this.$settings.version.length > 0) {
          $inps.version = this.$settings.version.find('input').eq(0);
          $inps.version.change(function(evt) {
            return _settings.set('version', $inps.version.val());
          });
        }
        if (this.$settings.style.length > 0) {
          $inps.style = this.$settings.style.find('input,select').eq(0);
          return $inps.style.change(function(evt) {
            return _settings.set('style', $inps.style.val());
          });
        }
      };

      SurveyFragmentApp.prototype._render_addSubViews = function() {
        var detail, meta_view, _i, _len, _ref1, _ref2;

        meta_view = new $viewUtils.ViewComposer();
        _ref1 = this.survey.surveyDetails.models;
        for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
          detail = _ref1[_i];
          if ((_ref2 = detail.get('name')) === "start" || _ref2 === "end" || _ref2 === "today" || _ref2 === "deviceid") {
            meta_view.add(new $surveyDetailView.SurveyDetailView({
              model: detail,
              selector: '.settings__first-meta'
            }));
          } else {
            meta_view.add(new $surveyDetailView.SurveyDetailView({
              model: detail,
              selector: '.settings__second-meta'
            }));
          }
        }
        meta_view.render();
        meta_view.attach_to(this.settingsBox);
        return this.null_top_row_view_selector = new $viewRowSelector.RowSelector({
          el: this.$el.find(".survey__row__spacer").get(0),
          survey: this.survey,
          ngScope: this.ngScope,
          surveyView: this,
          reversible: true
        });
      };

      SurveyFragmentApp.prototype._render_hideConditionallyDisplayedContent = function() {
        if (!this.features.displayTitle) {
          this.$(".survey-header__inner").hide();
        }
        if (!this.features.surveySettings) {
          this.$(".survey-header__options-toggle").hide();
        }
        if (!this.features.multipleQuestions) {
          this.$el.addClass('survey-editor--singlequestion');
          this.$el.find(".survey-editor__null-top-row").addClass("survey-editor__null-top-row--hidden");
          this.$el.find(".js-expand-row-selector").addClass("btn--hidden");
          if (this.survey.rows.length === 0) {
            this.null_top_row_view_selector.expand();
          }
        }
        if (!this.features.copyToLibrary) {
          return this.$el.find('.js-add-to-question-library').hide();
        }
      };

      SurveyFragmentApp.prototype.render = function() {
        var error;

        this.$el.addClass("survey-editor--loading");
        this.$el.removeClass("content--centered").removeClass("content");
        try {
          this._render_html();
          this._render_attachEvents();
          this._render_addSubViews();
          this._reset();
          this._render_hideConditionallyDisplayedContent();
        } catch (_error) {
          error = _error;
          this.$el.addClass("survey-editor--error");
          throw error;
        }
        this.$el.removeClass("survey-editor--loading");
        return this;
      };

      SurveyFragmentApp.prototype.set_multioptions_label = function() {
        var $expand_multioptions, icon;

        $expand_multioptions = this.$(".js-expand-multioptions--all");
        if (this.expand_all_multioptions()) {
          $expand_multioptions.html($expand_multioptions.html().replace("Show", "Hide"));
          icon = $expand_multioptions.find('i');
          icon.removeClass('fa-caret-right');
          return icon.addClass('fa-caret-down');
        } else {
          $expand_multioptions.html($expand_multioptions.html().replace("Hide", "Show"));
          icon = $expand_multioptions.find('i');
          icon.removeClass('fa-caret-down');
          return icon.addClass('fa-caret-right');
        }
      };

      SurveyFragmentApp.prototype.expandMultioptions = function() {
        var $expand_multioptions,
          _this = this;

        $expand_multioptions = this.$(".js-expand-multioptions--all");
        if (this.expand_all_multioptions()) {
          this.$(".card--expandedchoices").each(function(i, el) {
            _this._getViewForTarget({
              currentTarget: el
            }).hideMultioptions();
            return ;
          });
        } else {
          this.$(".card--selectquestion").each(function(i, el) {
            _this._getViewForTarget({
              currentTarget: el
            }).showMultioptions();
            return ;
          });
        }
        this.set_multioptions_label();
      };

      SurveyFragmentApp.prototype.closeWarningBox = function(evt) {
        return this.$('.survey-warnings').hide();
      };

      SurveyFragmentApp.prototype.getItemPosition = function(item) {
        var i;

        i = 0;
        while (item.length > 0) {
          item = item.prev();
          i++;
        }
        return i;
      };

      SurveyFragmentApp.prototype.activateSortable = function() {
        var $el, group_rows, sortable_activate_deactivate, sortable_stop, survey,
          _this = this;

        $el = this.formEditorEl;
        survey = this.survey;
        sortable_activate_deactivate = function(evt, ui) {
          var isActivateEvt;

          isActivateEvt = evt.type === 'sortactivate';
          ui.item.toggleClass('sortable-active', isActivateEvt);
          $el.toggleClass('insort', isActivateEvt);
          return _this.survey.trigger(evt.type);
        };
        sortable_stop = function(evt, ui) {
          $(ui.item).trigger('survey__row-sortablestop');
          return _this.survey.trigger('sortablestop');
        };
        this.formEditorEl.sortable({
          cancel: "button, .btn--addrow, .well, ul.list-view, li.editor-message, .editableform, .row-extras, .js-cancel-sort",
          cursor: "move",
          distance: 5,
          items: "> li",
          placeholder: "placeholder",
          connectWith: ".group__rows",
          opacity: 0.9,
          scroll: true,
          stop: sortable_stop,
          activate: sortable_activate_deactivate,
          deactivate: sortable_activate_deactivate,
          receive: function(evt, ui) {
            var item;

            if (ui.sender.hasClass('group__rows')) {
              return;
            }
            item = ui.item.prev();
            _this.ngScope.add_item(_this.getItemPosition(item) - 1);
            return ui.sender.sortable('cancel');
          }
        });
        group_rows = this.formEditorEl.find('.group__rows');
        group_rows.each(function(index) {
          $(this).sortable({
            cancel: 'button, .btn--addrow, .well, ul.list-view, li.editor-message, .editableform, .row-extras, .js-cancel-sort, .js-cancel-group-sort' + index,
            cursor: "move",
            distance: 5,
            items: "> li",
            placeholder: "placeholder",
            connectWith: ".group__rows, .survey-editor__list",
            opacity: 0.9,
            scroll: true,
            stop: sortable_stop,
            activate: sortable_activate_deactivate,
            deactivate: sortable_activate_deactivate
          });
          return $(this).attr('data-sortable-index', index);
        });
        group_rows.find('.survey__row').each(this._preventSortableIfGroupTooSmall);
      };

      SurveyFragmentApp.prototype._preventSortableIfGroupTooSmall = function(index, element) {
        var $element, class_name_matches;

        $element = $(element);
        class_name_matches = element.className.match(/js-cancel-group-sort\d+/g);
        if (class_name_matches != null) {
          $element.removeClass(class_name_matches.join(' '));
        }
        if ($element.siblings('.survey__row').length === 0) {
          return $element.addClass('js-cancel-group-sort' + ($element.closest('.group__rows').attr('data-sortable-index')));
        }
      };

      SurveyFragmentApp.prototype.validateSurvey = function() {
        if (!this.features.multipleQuestions) {
          return this.survey.rows.length === 1;
        }
        return this.survey._validate();
      };

      SurveyFragmentApp.prototype.previewCsv = function() {
        var scsv;

        scsv = this.survey.toCSV();
        if (typeof console !== "undefined" && console !== null) {
          console.clear();
        }
        log(scsv);
      };

      SurveyFragmentApp.prototype.ensureElInView = function(row, parentView, $parentEl) {
        var $el, detachRowEl, index, prevRow, prevRowEl, requiresInsertion, view;

        view = this.getViewForRow(row);
        $el = view.$el;
        index = row._parent.indexOf(row);
        if (index > 0) {
          prevRow = row._parent.at(index - 1);
        }
        if (prevRow) {
          prevRowEl = $parentEl.find(".survey__row[data-row-id=" + prevRow.cid + "]");
        }
        requiresInsertion = false;
        detachRowEl = function(detach) {
          $el.detach();
          return requiresInsertion = true;
        };
        if ($el.parents($parentEl).length === 0) {
          detachRowEl();
        } else if ($el.parent().get(0) !== $parentEl.get(0)) {
          detachRowEl();
        } else if (!prevRow) {
          if ($el.prev('.survey__row').not('.survey__row--deleted').data('rowId')) {
            detachRowEl();
          }
        } else if ($el.prev('.survey__row').not('.survey__row--deleted').data('rowId') !== prevRow.cid) {
          detachRowEl();
        }
        if (requiresInsertion) {
          if (prevRow) {
            $el.insertAfter(prevRowEl);
          } else {
            $el.appendTo($parentEl);
          }
        }
        return view;
      };

      SurveyFragmentApp.prototype.getViewForRow = function(row) {
        var rv, xlfrv;

        if (!(xlfrv = this.__rowViews.get(row.cid))) {
          if (row.constructor.kls === 'Group') {
            rv = new $rowView.GroupView({
              model: row,
              ngScope: this.ngScope,
              surveyView: this
            });
          } else if (row.get('type').getValue() === 'score') {
            rv = new $rowView.ScoreView({
              model: row,
              ngScope: this.ngScope,
              surveyView: this
            });
          } else if (row.get('type').getValue() === 'rank') {
            rv = new $rowView.RankView({
              model: row,
              ngScope: this.ngScope,
              surveyView: this
            });
          } else {
            rv = new $rowView.RowView({
              model: row,
              ngScope: this.ngScope,
              surveyView: this
            });
          }
          this.__rowViews.set(row.cid, rv);
          xlfrv = this.__rowViews.get(row.cid);
        }
        return xlfrv;
      };

      SurveyFragmentApp.prototype._reset = function() {
        var isEmpty, null_top_row,
          _this = this;

        _notifyIfRowsOutOfOrder(this);
        isEmpty = true;
        this.survey.forEachRow((function(row) {
          if (!_this.features.skipLogic) {
            row.unset('relevant');
          }
          isEmpty = false;
          return _this.ensureElInView(row, _this, _this.formEditorEl).render();
        }), {
          includeErrors: true,
          includeGroups: true,
          flat: true
        });
        this.set_multioptions_label();
        null_top_row = this.formEditorEl.find(".survey-editor__null-top-row").removeClass("expanded");
        null_top_row.toggleClass("survey-editor__null-top-row--hidden", !isEmpty);
        if (this.features.multipleQuestions) {
          this.activateSortable();
        }
      };

      SurveyFragmentApp.prototype.clickDeleteGroup = function(evt) {
        return this._getViewForTarget(evt).deleteGroup(evt);
      };

      SurveyFragmentApp.prototype.clickAddRowToQuestionLibrary = function(evt) {
        return this._getViewForTarget(evt).add_row_to_question_library(evt);
      };

      SurveyFragmentApp.prototype.clickCloneQuestion = function(evt) {
        return this._getViewForTarget(evt).clone();
      };

      SurveyFragmentApp.prototype.clickRemoveRow = function(evt) {
        var $et, findMatch, matchingRow, parent, rowEl, rowId,
          _this = this;

        evt.preventDefault();
        if (confirm("Are you sure you want to delete this question? This action cannot be undone.")) {
          $et = $(evt.target);
          rowEl = $et.parents(".survey__row").eq(0);
          rowId = rowEl.data("rowId");
          matchingRow = false;
          findMatch = function(r) {
            if (r.cid === rowId) {
              matchingRow = r;
            }
          };
          this.survey.forEachRow(findMatch, {
            includeGroups: false
          });
          if (!matchingRow) {
            throw new Error("Matching row was not found.");
          }
          parent = matchingRow._parent._parent;
          matchingRow.detach();
          rowEl.addClass('survey__row--deleted');
          rowEl.slideUp(175, "swing", function() {
            var parent_view;

            rowEl.remove();
            _this.survey.rows.remove(matchingRow);
            if (parent.constructor.kls === "Group" && parent.rows.length === 0) {
              parent_view = _this.__rowViews.get(parent.cid);
              if (!parent_view) {
                if (typeof trackJs !== "undefined" && trackJs !== null) {
                  trackJs.console.error("parent view is not defined", matchingRow.get('name').get('value'));
                }
              }
              return parent_view._deleteGroup();
            }
          });
          return this.set_multioptions_label();
        }
      };

      SurveyFragmentApp.prototype.groupSelectedRows = function() {
        var $q, rows;

        rows = this.selectedRows();
        $q = this.$('.survey__row--selected');
        $q.detach();
        $q.removeClass('survey__row--selected');
        this.activateGroupButton(false);
        if (rows.length > 0) {
          this.survey._addGroup({
            __rows: rows
          });
          this.reset();
          this.$('.js-group-rows').blur();
          return true;
        } else {
          return false;
        }
      };

      SurveyFragmentApp.prototype.selectedRows = function() {
        var rows,
          _this = this;

        rows = [];
        this.$el.find('.survey__row--selected').each(function(i, el) {
          var $el, findMatch, matchingRow, rowId;

          $el = $(el);
          if ($el.parents('li.survey__row--group.survey__row--selected').length > 0) {
            return;
          }
          rowId = $el.data("rowId");
          matchingRow = false;
          findMatch = function(row) {
            if (row.cid === rowId) {
              return matchingRow = row;
            }
          };
          _this.survey.forEachRow(findMatch, {
            includeGroups: true
          });
          return rows.push(matchingRow);
        });
        return rows;
      };

      SurveyFragmentApp.prototype.onEscapeKeydown = function() {};

      SurveyFragmentApp.prototype.previewButtonClick = function(evt) {
        var content, _ref1, _ref2, _ref3,
          _this = this;

        if (evt.shiftKey) {
          evt.preventDefault();
          if (evt.altKey) {
            content = this.survey.toCSV();
          } else {
            content = JSON.stringify(this.survey.toJSON(), null, 4);
          }
          $viewUtils.debugFrame(content.replace(new RegExp(' ', 'g'), '&nbsp;'));
          this.onEscapeKeydown = $viewUtils.debugFrame.close;
        } else {
          $viewUtils.enketoIframe.fromCsv(this.survey.toCSV(), {
            previewServer: ((_ref1 = window.koboConfigs) != null ? _ref1.previewServer : void 0) || "http://kf.kobotoolbox.org",
            enketoServer: ((_ref2 = window.koboConfigs) != null ? _ref2.enketoServer : void 0) || false,
            enketoPreviewUri: ((_ref3 = window.koboConfigs) != null ? _ref3.enketoPreviewUri : void 0) || false,
            onSuccess: function() {
              return _this.onEscapeKeydown = $viewUtils.enketoIframe.close;
            },
            onError: function(message, opts) {
              return _this.alert(message, opts);
            }
          });
        }
      };

      SurveyFragmentApp.prototype.alert = function(message, opts) {
        var title;

        if (opts == null) {
          opts = {};
        }
        title = opts.title || 'Error';
        return $('.alert-modal').html(message).dialog('option', {
          title: title,
          width: 500,
          dialogClass: 'surveyapp__alert'
        }).dialog('open');
      };

      SurveyFragmentApp.prototype.downloadButtonClick = function(evt) {
        var surveyCsv;

        surveyCsv = this.survey.toCSV();
        if (surveyCsv) {
          return evt.target.href = "data:text/csv;charset=utf-8," + (encodeURIComponent(this.survey.toCSV()));
        }
      };

      SurveyFragmentApp.prototype.saveButtonClick = function(evt) {
        var icon;

        icon = $(evt.currentTarget).find('i');
        icon.addClass('fa-spinner fa-spin blue');
        icon.removeClass('fa-check-circle green');
        return this.onSave.apply(this, arguments)["finally"](function() {
          icon.removeClass('fa-spinner fa-spin blue');
          return icon.addClass('fa-check-circle green');
        });
      };

      SurveyFragmentApp.prototype.publishButtonClick = function(evt) {
        return this.onPublish.apply(this, arguments);
      };

      SurveyFragmentApp.prototype.toggleLibrary = function(evt) {
        var $et;

        evt.stopPropagation();
        $et = $(evt.target);
        $et.toggleClass('active__sidebar');
        $("section.form-builder").toggleClass('active__sidebar');
        this.ngScope.displayQlib = !this.ngScope.displayQlib;
        this.ngScope.$apply();
        $("section.koboform__questionlibrary").toggleClass('active').data("rowIndex", -1);
      };

      SurveyFragmentApp.prototype.buttonHoverIn = function(evt) {
        var $et, buttonName;

        evt.stopPropagation();
        $et = $(evt.currentTarget);
        buttonName = $et.data('buttonName');
        $et.parents('.card').addClass('card--shaded');
        $et.parents('.card__header').addClass(buttonName);
      };

      SurveyFragmentApp.prototype.buttonHoverOut = function(evt) {
        var $et, buttonName;

        evt.stopPropagation();
        $et = $(evt.currentTarget);
        buttonName = $et.data('buttonName');
        $et.parents('.card__header').removeClass(buttonName);
        $et.parents('.card').removeClass('card--shaded');
      };

      return SurveyFragmentApp;

    })($baseView);
    surveyApp.SurveyApp = (function(_super) {
      __extends(SurveyApp, _super);

      function SurveyApp() {
        _ref1 = SurveyApp.__super__.constructor.apply(this, arguments);
        return _ref1;
      }

      SurveyApp.prototype.features = {
        multipleQuestions: true,
        skipLogic: true,
        displayTitle: true,
        copyToLibrary: true,
        surveySettings: true
      };

      return SurveyApp;

    })(SurveyFragmentApp);
    surveyApp.QuestionApp = (function(_super) {
      __extends(QuestionApp, _super);

      function QuestionApp() {
        _ref2 = QuestionApp.__super__.constructor.apply(this, arguments);
        return _ref2;
      }

      QuestionApp.prototype.features = {
        multipleQuestions: false,
        skipLogic: false,
        displayTitle: false,
        copyToLibrary: false,
        surveySettings: false
      };

      QuestionApp.prototype.render = function() {
        QuestionApp.__super__.render.apply(this, arguments);
        return this.$('.survey-editor.form-editor-wrap.container').append($('.question__tags'));
      };

      return QuestionApp;

    })(SurveyFragmentApp);
    surveyApp.SurveyTemplateApp = (function(_super) {
      __extends(SurveyTemplateApp, _super);

      function SurveyTemplateApp() {
        _ref3 = SurveyTemplateApp.__super__.constructor.apply(this, arguments);
        return _ref3;
      }

      SurveyTemplateApp.prototype.events = {
        "click .js-start-survey": "startSurvey"
      };

      SurveyTemplateApp.prototype.initialize = function(options) {
        this.options = options;
      };

      SurveyTemplateApp.prototype.render = function() {
        this.$el.addClass("content--centered").addClass("content");
        this.$el.html($viewTemplates.$$render('surveyTemplateApp'));
        return this;
      };

      SurveyTemplateApp.prototype.startSurvey = function() {
        return new surveyApp.SurveyApp(this.options).render();
      };

      return SurveyTemplateApp;

    })($baseView);
    return surveyApp;
  });

}).call(this);


(function() {
  define('cs!xlform/_view', ['underscore', 'cs!xlform/view.surveyApp', 'cs!xlform/view.utils', 'cs!xlform/view.rowDetail.SkipLogic'], function(_, $surveyApp, $viewUtils, $viewRowDetailSkipLogic) {
    var view;

    view = {};
    _.extend(view, $surveyApp);
    view.utils = $viewUtils;
    view.rowDetailSkipLogic = $viewRowDetailSkipLogic;
    return view;
  });

}).call(this);


/*
License: BSD 2-clause License (From http://github.com/dorey/xlform-builder/LICENSE.md)

Copyright (c) 2013, Alex Dorey
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this list
    of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright notice, this
    list of conditions and the following disclaimer in the documentation and/or other
    materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/


(function() {
  define('cs!xlform/_xlform.init', ['cs!xlform/_model', 'cs!xlform/_view', 'cs!xlform/mv.skipLogicHelpers'], function($model, $view, $skipLogicHelpers) {
    var XLF;

    XLF = {
      model: $model,
      view: $view,
      helper: {
        skipLogic: $skipLogicHelpers
      }
    };
    return XLF;
  });

}).call(this);

// tells the r.js loader to include these modules
require(['cs!xlform/_xlform.init']);

(function(){
  if ( !this.dkobo_xlform ) {
    this.dkobo_xlform = require('cs!xlform/_xlform.init');
  }
})();

define("build_configs/dkobo_xlform", function(){});

}());