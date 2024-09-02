const path = require('path')
const fs = require('fs');
const readline = require('readline');

const PATH_TO_FBENCH = path.dirname(__filename);

if (process.argv.length < 3) {
    console.log("usage: run.js <program-name>");
    process.exit(0);
}

if (!global.gc) {
    console.log("please run with --expose-gc");
    process.exit(0);
}

const name = process.argv[2];

var module = null;
var handler = null;

try {
    module = require(`${PATH_TO_FBENCH}/${name}`);

    if (module && module.function_handler) {
	handler = module.function_handler;
    } else {
	console.log(`module ${name} missing function_handler`);
    }
} catch (error) {
    console.log(`Error: could not load module ${name}.js: ${error}`);
}

if (handler == null) {
    process.exit(0);
}

function snapshot_prepare() {
    for (let i = 0; i < 3; i++) {
	global.gc()
    }
}

async function readLines(filePath) {
    const read = fs.createReadStream(filePath);
    const write = fs.createWriteStream(filePath);

    const rl = readline.createInterface({
        input: read,
        crlfDelay: Infinity
    });

    for await (const line of rl) {
	if (line == "SNAPSHOT_PREPARE") {
	    snapshot_prepare();
	    await write.write("OK");
	    continue;
	}

	// invoke function
	json_req = JSON.parse(line)
	const ret = await handler(json_req);
	await write.write(ret);
    }
}

readLines('/serverless/chan0');
