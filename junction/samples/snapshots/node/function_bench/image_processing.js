const sharp = require('/usr/local/lib/node_modules/sharp');
const fs = require('fs');
const path = require('path');

const TMP = "/tmp/"

async function resize(arg) {
    try {
	const image_path = arg.path;
	const file_name = path.basename(image_path);

	const data = await fs.promises.readFile(image_path);

	await sharp(data)
	    .resize(720, 720)
	    .toFile(TMP + "thumb-" + file_name);
	await console.log("Done resize");
    } catch (err) {
	await console.log(err);
    }
}

async function function_handler(arg) {

    await resize(arg);

    return " ";
}

module.exports = { function_handler };
