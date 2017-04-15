#set terminal postscript eps enhanced "NimbusSanL-Regu, 24" fontfile "/usr/share/texlive/texmf-dist/fonts/type1/urw/helvetic/uhvr8a.pfb"

set terminal windows
set border 3
set style fill solid
set style data histogram
set style histogram cluster gap 1
set style line 1 lt 1 lc rgb "blue"
set style line 2 lt 2 lc rgb "#00ff00"
set style line 3 lt 3 lc rgb "#E91717"
set key right
set key spacing 1.5

set xrange[-0.75:8]
set yrange [0:300]

set xtics nomirror
set ytics nomirror

set key font ",15"
set ylabel "Network Bandwidth (KBps)"

set xtics font ",10"
set xtics ("Redis" 0, "SSDB" 1, "MongoDB" 2, "Memcached" 3 , "MySQL" 4, "Apache" 5)

set ytics font ",10"
set ytics ("0" 0, "50" 50,  "100" 100,  "150" 150,  "200" 200,  "250" 250,  "300" 300,  "350" 350,  "400" 400)



set boxwidth 0.50 absolute
set key font ",15"
plot 'FIG2__network_badwidth.dat' using 2 ls 1 fs pattern 2 title "Remus",\
'FIG2__network_bandwidth.dat' using 3 ls 2 fs pattern 4 title "vSphere", \
'FIG2__network_bandwidth.dat' using 4 ls 3 fs pattern 5 title "xxx"