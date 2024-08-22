const sharp = require('/usr/local/lib/node_modules/sharp');
const fs = require('fs');
const path = require('path');

const TMP = "/tmp/"

function flip(image, file_name) {
    var path = TMP + "flip-left-right-" + file_name;
    sharp(image)
	.flop()
        .toFile(path);

    path = TMP + "flip-top-bottom-" + file_name;
    sharp(image)
	.flip()
        .toFile(path);
}

function rotate(image, file_name) {
    var path = TMP + "rotate-90-" + file_name;
    sharp(image)
	.rotate(90)
	.toFile(path);

    path = TMP + "rotate-180-" + file_name;
    sharp(image)
	.rotate(180)
	.toFile(path);

    path = TMP + "rotate-270-" + file_name;
    sharp(image)
	.rotate(270)
	.toFile(path);
}

function filter(image, file_name) {
    var path = TMP + "blur-" + file_name;
    sharp(image)
	.blur(5)
	.toFile(path);

    path = TMP + "sharpen-" + file_name;
    sharp(image)
	.sharpen()
	.toFile(path);
}

function image_processing(file_name, stream) {
    flip(stream, file_name);
    rotate(stream, file_name);
}

function function_handler(arg) {
    const image_path = arg.path;
    const file_name = path.basename(image_path);

    fs.readFile(image_path, (err, data) => {
	if (err) {
	    console.error("Error reading file: ", err);
	    return;
	}

	image_processing(file_name, data);
    });

    return " "
}

module.exports = { function_handler };
