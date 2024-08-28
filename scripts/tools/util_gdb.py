import gdb


class RestoreRegistersFromContext(gdb.Command):
    """Restore registers from a signal handler context."""

    def __init__(self):
        super(
            RestoreRegistersFromContext,
            self).__init__(
            "restore-registers",
            gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not arg:
            print("Usage: restore-registers <context address>")
            return

        context_address = int(arg, 0)
        context_type = gdb.lookup_type("junction::k_ucontext").pointer()
        context = gdb.Value(context_address).cast(context_type)
        mcontext = context['uc_mcontext']

        # Restore general-purpose registers
        for reg in [
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rdi",
            "rsi",
            "rbp",
            "rbx",
            "rdx",
            "rax",
            "rcx",
            "rsp",
            "rip",
                "eflags"]:
            gdb.execute(f"set ${reg} = {mcontext[reg]}")

        print("Registers restored from context. You can now perform backtracing.")


RestoreRegistersFromContext()


class RestoreBlockedThread(gdb.Command):
    """Restore registers from a blocked Caladan thread."""

    def __init__(self):
        super(
            RestoreBlockedThread,
            self).__init__(
            "restore-thread",
            gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not arg:
            print("Usage: restore-thread <thread address>")
            return

        context_address = int(arg, 0)
        context_type = gdb.lookup_type("thread_t").pointer()
        thread = gdb.Value(context_address).cast(context_type)
        tf = thread['tf']

        # Restore general-purpose registers
        for reg in [
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rdi",
            "rsi",
            "rbp",
            "rbx",
            "rdx",
            "rax",
            "rcx",
            "rsp",
                "rip"]:
            gdb.execute(f"set ${reg} = {tf[reg]}")

        print("Registers restored from caladan thread. You can now backtrace.")


RestoreBlockedThread()
