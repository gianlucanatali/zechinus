const { defineStore } = require("../dist-cjs/index.cjs");
if (typeof defineStore !== "function") throw new Error("CJS build broken: defineStore is not a function");
console.log("CJS consumption OK");
