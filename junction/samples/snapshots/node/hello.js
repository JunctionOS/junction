const snapshot = require('./build/Release/snapshot');

console.log("Do a print to warm up");
console.log(process.argv.length);

if (process.argv.length > 2) {

    var elf = "/tmp/junction.elf"
    var metadata = "/tmp/junction.metadata"

    if (process.argv.length == 4) {
	metadata = process.argv[3];
	elf = process.argv[2];
    }
    
    var ret = snapshot.snapshot(elf, metadata);

    if(ret == 0) {
	console.log("Snapshotted!");
    } else {
	console.log("Restored!");
    }
}

// this will explicitly kill the process
process.abort();

