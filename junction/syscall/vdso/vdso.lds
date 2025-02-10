LINUX_2.6 {
    global:
        __vdso_clock_gettime;
        __vdso_getcpu;
        __vdso_clock_getres;
        __vdso_time;
        __vdso_gettimeofday;
        clock_gettime;
        getcpu;
        clock_getres;
        time;
        gettimeofday;
    local:
        *;  /* Hide all other symbols */
};