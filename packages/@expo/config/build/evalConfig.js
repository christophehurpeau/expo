"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.evalConfig = evalConfig;
exports.resolveConfigExport = resolveConfigExport;
function _esbuild() {
  const data = require("esbuild");
  _esbuild = function () {
    return data;
  };
  return data;
}
function _fs() {
  const data = require("fs");
  _fs = function () {
    return data;
  };
  return data;
}
function _requireFromString() {
  const data = _interopRequireDefault(require("require-from-string"));
  _requireFromString = function () {
    return data;
  };
  return data;
}
function _Errors() {
  const data = require("./Errors");
  _Errors = function () {
    return data;
  };
  return data;
}
function _Serialize() {
  const data = require("./Serialize");
  _Serialize = function () {
    return data;
  };
  return data;
}
function _environment() {
  const data = require("./environment");
  _environment = function () {
    return data;
  };
  return data;
}
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
/**
 * Transpile and evaluate the dynamic config object.
 * This method is shared between the standard reading method in getConfig, and the headless script.
 *
 * @param options configFile path to the dynamic app.config.*, request to send to the dynamic config if it exports a function.
 * @returns the serialized and evaluated config along with the exported object type (object or function).
 */
function evalConfig(configFile, request) {
  const contents = (0, _fs().readFileSync)(configFile, 'utf8');
  let result;
  try {
    const {
      code
    } = (0, _esbuild().transformSync)(contents, {
      loader: configFile.endsWith('.ts') ? 'ts' : 'js',
      format: 'cjs',
      target: 'node14',
      sourcefile: configFile
    });
    result = (0, _requireFromString().default)(code, configFile);
  } catch (error) {
    if (error.errors) {
      throw new Error((0, _esbuild().formatMessagesSync)(error.errors, {
        kind: 'error'
      }).join('\n'));
    }
    throw error;
  }
  return resolveConfigExport(result, configFile, request);
}

/**
 * - Resolve the exported contents of an Expo config (be it default or module.exports)
 * - Assert no promise exports
 * - Return config type
 * - Serialize config
 *
 * @param result
 * @param configFile
 * @param request
 */
function resolveConfigExport(result, configFile, request) {
  // add key to static config that we'll check for after the dynamic is evaluated
  // to see if the static config was used in determining the dynamic
  const hasBaseStaticConfig = _environment().NON_STANDARD_SYMBOL;
  if (request?.config) {
    // @ts-ignore
    request.config[hasBaseStaticConfig] = true;
  }
  if (result.default != null) {
    result = result.default;
  }
  const exportedObjectType = typeof result;
  if (typeof result === 'function') {
    result = result(request);
  }
  if (result instanceof Promise) {
    throw new (_Errors().ConfigError)(`Config file ${configFile} cannot return a Promise.`, 'INVALID_CONFIG');
  }

  // If the key is not added, it suggests that the static config was not used as the base for the dynamic.
  // note(Keith): This is the most common way to use static and dynamic config together, but not the only way.
  // Hence, this is only output from getConfig() for informational purposes for use by tools like Expo Doctor
  // to suggest that there *may* be a problem.
  const mayHaveUnusedStaticConfig =
  // @ts-ignore
  request?.config?.[hasBaseStaticConfig] && !result?.[hasBaseStaticConfig];
  if (result) {
    delete result._hasBaseStaticConfig;
  }

  // If the expo object exists, ignore all other values.
  if (result?.expo) {
    result = (0, _Serialize().serializeSkippingMods)(result.expo);
  } else {
    result = (0, _Serialize().serializeSkippingMods)(result);
  }
  return {
    config: result,
    exportedObjectType,
    mayHaveUnusedStaticConfig
  };
}
//# sourceMappingURL=evalConfig.js.map