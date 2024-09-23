function function_handler(arg) {
    // const start = process.hrtime();
    // process.stdout.write(`${arg.test} test\n`);
    // const end = process.hrtime(start);
    return `${arg.test} test\n`;
}

module.exports = { function_handler };
