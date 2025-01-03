import mmap
import os
import random

# Constants
PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')  # Get the system's page size
TOTAL_PAGES = 1024 * 1024  # 1 million pages (~4GB if page size is 4KB)
MMAP_SIZE = TOTAL_PAGES * PAGE_SIZE

mem = None
access_sequence = None

def create_memory_map():
    """Create an mmap-backed memory region."""
    global mem, access_sequence
    mem = mmap.mmap(-1, MMAP_SIZE, mmap.MAP_PRIVATE | mmap.MAP_ANON, mmap.PROT_READ | mmap.PROT_WRITE)
    print(f"Memory-mapped {MMAP_SIZE / (1024 * 1024)} MB")

    # Create a random access pattern of pages.
    access_sequence = list(range(TOTAL_PAGES))
    random.shuffle(access_sequence)

    # Write to each page
    for i in range(TOTAL_PAGES):
        mem[i * PAGE_SIZE] = random.randint(0, 255)

def touch_and_compute(num_pages, float_ops_per_page, sequential):
    global mem
    """
    Touch a number of pages in the mmap'd area and perform float operations per page.

    :param mem: The memory-mapped object.
    :param num_pages: Number of pages to touch.
    :param float_ops_per_page: Number of floating-point operations per touched page.
    """
    if num_pages > TOTAL_PAGES:
        raise ValueError(f"Cannot touch more than {TOTAL_PAGES} pages.")

    result = 0.0
    for i in range(num_pages):
        # Calculate offset for the current page
        if not sequential:
            offset = access_sequence[i] * PAGE_SIZE
        else:
            offset = i * PAGE_SIZE

        # Write a byte to ensure the page is touched
        result += mem[offset]

        # Perform floating-point operations
        for _ in range(float_ops_per_page):
            result += 1.0 / (1.0 + float(result))

    return str(result)

def function_handler(request_json):
    num_pages = request_json["num_pages"]
    float_ops_per_page = request_json["ops_per_page"]
    sequential = request_json.get("sequential", False)
    return touch_and_compute(num_pages, float_ops_per_page, sequential)

create_memory_map()

