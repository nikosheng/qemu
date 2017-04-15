set terminal windows
set border 3

set title "Scalable Key Range"

set xrange[0.5:11]
set yrange [0:150]

set xlabel "Key Range"
set xtics font ",10"
set xtics ("100" 2, "10000" 4, "100000" 6, "1000000" 8, "10000000" 10)

set ylabel "Throughput"
set ytics "10"
plot "FIG4__scalable_keyrange.dat" using 2 title "vSphere" with lines, \
"FIG4__scalable_keyrange.dat" using 3 title "Remus" with lines, \
"FIG4__scalable_keyrange.dat" using 4 title "xxx" with lines