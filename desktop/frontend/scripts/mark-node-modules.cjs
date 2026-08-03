const fs = require("fs");
const path = require("path");

const target = path.join(__dirname, "..", "node_modules", "go.mod");

if (fs.existsSync(path.dirname(target))) {
  fs.writeFileSync(target, "module whitedns-desktop-node-modules\n\ngo 1.23.0\n");
}

