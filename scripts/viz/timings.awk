#!awk -f
#
# usage: timings.awk -v regex=[;-separated list of regex] -v scale=[ms|milli|us|micro|s|sec]

BEGIN {
    if ( length(regex) == 0 ) {
        regex="."
    }
    if ( length(scale) == 0 ) {
        scale="s"
    }

    split(regex, regexlist, ";")

    if ( scale != "s" && scale != "sec" && scale != "secs" && scale != "ms" && scale != "milli" && scale != "millis" && scale != "us" && scale != "micro" && scale != "micros" ) {
        print "invalid scale: `" scale "`"
        print "usage: timings.awk -v regex=[;-separated list of regex] -v scale=[ms|milli|us|micro|s|sec]"
        exit
    }

    if ( scale == "s" || scale == "sec" || scale == "secs") {
        scale = "s"
    } else if ( scale == "ms" || scale == "milli" || scale == "millis") {
        scale = "ms"
    } else if ( scale == "us" || scale == "micro" || scale == "micros") {
        scale = "us"
    }

    n_records = 0
    prev_time = 0
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

    if ( n_records > 1 ) {
        trace[n_records] = message
        delta[n_records] = time - prev_time
    }

    prev_time = time
}

END {
    for ( i = 2; i <= n_records; i++ ) {
        time_delta = timings[i] - timings[i - 1]
        message = trace[timings[i]]
        if (scale == "s") {
            printf "%.7f\t\"%s\"\n", delta[i] , trace[i]
        } else if ( scale == "ms") {
            printf "%.4f\t\"%s\"\n", delta[i] * 1000, trace[i]
        } else if ( scale == "us") {
            printf "%.1f\t\"%s\"\n", delta[i] * 1000000, trace[i]
        }
    }
}
