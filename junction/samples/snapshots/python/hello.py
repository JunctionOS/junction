import snapshot
import sys

if __name__ == "__main__":
    print("Hello world!")

    if len(sys.argv) > 1:
        elf = "/tmp/junction.elf"
        metadata = "/tmp/junction.metadata"
        
        if len(sys.argv) > 3:
            metadata = sys.argv[2]
            elf = sys.argv[3]

        # flush to make sure the stuff from above isn't printed when we are restored
        sys.stdout.flush()

        ret = snapshot.snapshot(elf, metadata)
        if ret:
            print("Snapshotted!")
        else:
            print("Restored!")

