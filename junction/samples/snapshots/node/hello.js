console.log("Do a print to warm up");

process.kill(process.pid, "SIGSTOP")

console.log("Restored!");

// this will explicitly kill the process
process.exit(0);
