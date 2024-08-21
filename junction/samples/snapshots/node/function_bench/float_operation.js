function function_handler(arg) {
    let N = arg.N;
    const start = process.hrtime();
    for (let i = 0; i < N; i++) {
	sin_i = Math.sin(i);
	cos_i = Math.cos(i);
	sqrt_i = Math.sqrt(i);
    }
    const end = process.hrtime(start);
    return `latency : ${end[0] * 1000000 + end[1]/1000}`;
}

module.exports = { function_handler };
