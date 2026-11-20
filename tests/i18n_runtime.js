// Runs the translation helpers of frontend/js/app.js outside a browser. Used by tests/test_i18n.py:
//   node tests/i18n_runtime.js <app.js> <dictionary.json> <cases.json>   ->  JSON list of translated strings
const fs = require("fs");
const [appPath, dictPath, casesPath] = process.argv.slice(2);
const src = fs.readFileSync(appPath, "utf8");
const a = src.indexOf("const I18N = {");
const b = src.indexOf("// Text that reaches the page without el()");
if (a < 0 || b < 0) throw new Error("translation helpers not found in app.js");
const dict = JSON.parse(fs.readFileSync(dictPath, "utf8"));
const cases = JSON.parse(fs.readFileSync(casesPath, "utf8"));
const run = new Function("dict", "cases", `${src.slice(a, b)}
  I18N.dict = dict; I18N.pats = compilePatterns(dict);
  return cases.map((s) => tr(s));`);
process.stdout.write(JSON.stringify(run(dict, cases)));
