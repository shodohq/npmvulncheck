"use strict";

const path = require("node:path");

const depCResolvedPath = path.join(__dirname, ".yarn", "__virtual__", "dep-c", "index.js");

module.exports = {
  resolveRequest(request, _issuer, _opts) {
    if (request === "dep-c") {
      return depCResolvedPath;
    }
    return null;
  },
  findPackageLocator(location) {
    if (location === depCResolvedPath || location.startsWith(path.dirname(depCResolvedPath))) {
      return {
        name: "dep-c",
        reference: "npm:2.2.0"
      };
    }
    return null;
  }
};
