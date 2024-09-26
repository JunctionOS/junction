const fs = require('fs');

async function function_handler(arg) {
    const json_path = arg.json_path;

    const data = await fs.promises.readFile(json_path);
    const json_data = await JSON.parse(data);
    const string = await JSON.stringify(json_data);

    return " ";
}

module.exports = { function_handler };
