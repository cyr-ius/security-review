// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Archive entries written outside the target directory (zip slip).
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');

function extract(file, target) {
  for (const entry of new AdmZip(file).getEntries()) {
    // ruleid: secreview.js.zip-slip
    fs.writeFileSync(path.join(target, entry.entryName), entry.getData());
  }
}

function extractSafely(file, target) {
  for (const entry of new AdmZip(file).getEntries()) {
    // ok: secreview.js.zip-slip
    const destination = path.resolve(target, entry.entryName);
    if (!destination.startsWith(path.resolve(target) + path.sep)) {
      throw new Error('zip slip');
    }
    fs.writeFileSync(destination, entry.getData());
  }
}
