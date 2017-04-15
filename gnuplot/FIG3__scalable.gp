set terminal windows
set border 3

set title "Scalable"

set xrange[0.5:11]
set yrange [0:150]

set xlabel "CPU Core(s)"
set xtics font ",10"
set xtics ("1" 2, "2" 4, "4" 6, "8" 8, "16" 10)

set ylabel "Throughput"
set ytics "10"
plot "FIG3__scalable.dat" using 2 title "SSDB" with lines, \
"FIG3__scalable.dat" using 3 title "Bandwidth" with lines