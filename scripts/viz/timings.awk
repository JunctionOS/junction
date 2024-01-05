#!awk -f

BEGIN {
    if ( length(output_mode) == 0 ) {
        output_mode = "json"
    }

    if ( length(regex) == 0 ) {
        regex="."
    }

    if ( output_mode != "json" && output_mode != "dat" ) {
        print "invalid output mode: `" output_mode "`"
        print "usage: timings.awk -v output_mode=[json|dat] -v regex=[;-separated list of regex]"
        exit
    }

    split(regex, regexlist, ";")

    n_records = 0
}

# return 0 if no match is found
# return the match index if it is found
function array_match(string, regex_array) {
    for ( i = 1; i <= length(regex_array); i++ ) {
        match_index = match(string, regex_array[i])
        if ( match_index != 0 ) {
            return match_index
        }
    }

    return 0
}

/^\[[ \t]*[0-9]+\.[0-9]+\]/ {
    message = $6;
    for (i = 7; i <= NF; i++) {
        message = message " " $i;
    }

    if ( array_match(message, regexlist) == 0 ) {
        next
    }

    n_records += 1
    time=gensub(/\]/, "", "g", $2);


    trace[time] = message
    timings[n_records] = time
}

END {
    asort(timings)
    n_timings = length(timings)
    if (output_mode == "json") {
        printf "{\n"
        for ( i = 1; i < n_timings; i++) {
            printf "\t\"%s\": \"%s\",\n", timings[i], trace[timings[i]]
        }
        if ( n_timings > 0 ) {
            printf "\t\"%s\": \"%s\"\n", timings[n_timings], trace[timings[n_timings]]
        }
        printf "}\n"
    } else {
        for ( i = 1; i <= n_timings; i++) {
            printf "%s  \"%s\"\n", timings[i], trace[timings[i]]
        }
    }
}
