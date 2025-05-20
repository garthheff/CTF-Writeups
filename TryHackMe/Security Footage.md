Perform digital forensics on a network capture to recover footage from a camera.

Someone broke into our office last night, but they destroyed the hard drives with the security footage. Can you recover the footage?

Note: If you are using the AttackBox, you can find the task files inside the `/root/Rooms/securityfootage/` directory.

What is the flag?
# Reconnaissance 

Finding the pcap 
```
oot@ip-10-10-53-81:~# cd /root/Rooms/securityfootage/
root@ip-10-10-53-81:~/Rooms/securityfootage# ls
securityfootage.pcap
```

Reviewing in wireshark shows TCP streams of image files, 

```
GET / HTTP/1.1
Host: 192.168.1.100:8081
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1


HTTP/1.1 200 OK
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: multipart/x-mixed-replace; boundary=BoundaryString
Date: Sat, 02 Apr 2022 20:31:18 GMT

2906
--BoundaryString
Content-type: image/jpeg
Content-Length:     10427
```

# Extracting images 

Installing tcpflow
```
apt install tcpflow
```

Reconstruct TCP streams
```
tcpflow -r securityfootage.pcap -o tcpdump_output/
```

get stream names
```
ls tcpdump_output/
```

foremost can carve JPEGs (`.jpg`) based on magic headers.
```
foremost -i tcpdump_output/192.168.001.100.08081-010.000.002.015.42312 -o mjpeg_carve
```

From here you can view images, 
```
ls mjpeg_carve/jpg/
```

Although you can make into a video, 

```
ffmpeg -framerate 5 -pattern_type glob -i 'mjpeg_carve/jpg/*.jpg' -c:v libx264 -pix_fmt yuv420p out.mp4
```

Full command outputs

```
root@ip-10-10-53-81:~/Rooms/securityfootage# ls tcpdump_output/
010.000.002.015.42312-192.168.001.100.08081  192.168.001.100.08081-010.000.002.015.42312  report.xml
root@ip-10-10-53-81:~/Rooms/securityfootage# 
root@ip-10-10-53-81:~/Rooms/securityfootage# ls -la tcpdump_output/
total 5844
drwxr-xr-x 2 root root    4096 May 20 05:12 .
drwxr-xr-x 3 root root    4096 May 20 05:12 ..
-rw-r--r-- 1 root root     348 Apr  2  2022 010.000.002.015.42312-192.168.001.100.08081
-rw-r--r-- 1 root root 5962853 Apr  2  2022 192.168.001.100.08081-010.000.002.015.42312
-rw-r--r-- 1 root root    4254 May 20 05:12 report.xml
root@ip-10-10-53-81:~/Rooms/securityfootage# foremost -i tcpdump_output/192.168.001.100.08081-010.000.002.015.42312 -o mjpeg_carve
Processing: tcpdump_output/192.168.001.100.08081-010.000.002.015.42312
|*|
root@ip-10-10-53-81:~/Rooms/securityfootage# 
root@ip-10-10-53-81:~/Rooms/securityfootage# ls mjpeg_carve/jpg/
00000000.jpg  00000587.jpg  00001198.jpg  00001802.jpg  00002409.jpg  00003011.jpg  00003615.jpg  00004212.jpg  00004822.jpg  00005433.jpg  00006038.jpg  00006645.jpg  00007246.jpg  00007839.jpg  00008433.jpg  00009046.jpg  00009653.jpg  00010264.jpg  00010877.jpg  00011469.jpg
00000021.jpg  00000609.jpg  00001220.jpg  00001823.jpg  00002430.jpg  00003033.jpg  00003636.jpg  00004234.jpg  00004844.jpg  00005454.jpg  00006060.jpg  00006667.jpg  00007268.jpg  00007860.jpg  00008455.jpg  00009067.jpg  00009675.jpg  00010286.jpg  00010899.jpg  00011489.jpg
00000041.jpg  00000630.jpg  00001242.jpg  00001844.jpg  00002452.jpg  00003055.jpg  00003658.jpg  00004255.jpg  00004866.jpg  00005476.jpg  00006081.jpg  00006688.jpg  00007290.jpg  00007880.jpg  00008477.jpg  00009089.jpg  00009697.jpg  00010308.jpg  00010920.jpg  00011508.jpg
00000061.jpg  00000652.jpg  00001264.jpg  00001866.jpg  00002473.jpg  00003076.jpg  00003679.jpg  00004277.jpg  00004888.jpg  00005497.jpg  00006103.jpg  00006709.jpg  00007311.jpg  00007901.jpg  00008499.jpg  00009111.jpg  00009719.jpg  00010330.jpg  00010942.jpg  00011528.jpg
00000081.jpg  00000674.jpg  00001286.jpg  00001887.jpg  00002495.jpg  00003098.jpg  00003701.jpg  00004298.jpg  00004910.jpg  00005519.jpg  00006125.jpg  00006730.jpg  00007333.jpg  00007922.jpg  00008520.jpg  00009133.jpg  00009741.jpg  00010352.jpg  00010964.jpg  00011548.jpg
00000102.jpg  00000695.jpg  00001308.jpg  00001909.jpg  00002516.jpg  00003119.jpg  00003722.jpg  00004320.jpg  00004932.jpg  00005541.jpg  00006146.jpg  00006752.jpg  00007355.jpg  00007943.jpg  00008542.jpg  00009154.jpg  00009763.jpg  00010374.jpg  00010985.jpg  00011567.jpg
00000123.jpg  00000717.jpg  00001330.jpg  00001930.jpg  00002538.jpg  00003141.jpg  00003744.jpg  00004342.jpg  00004953.jpg  00005563.jpg  00006168.jpg  00006773.jpg  00007376.jpg  00007964.jpg  00008564.jpg  00009175.jpg  00009784.jpg  00010396.jpg  00011007.jpg  00011587.jpg
00000144.jpg  00000739.jpg  00001351.jpg  00001952.jpg  00002559.jpg  00003162.jpg  00003765.jpg  00004364.jpg  00004975.jpg  00005584.jpg  00006190.jpg  00006795.jpg  00007398.jpg  00007985.jpg  00008585.jpg  00009197.jpg  00009806.jpg  00010418.jpg  00011029.jpg  00011607.jpg
00000165.jpg  00000760.jpg  00001373.jpg  00001973.jpg  00002581.jpg  00003184.jpg  00003786.jpg  00004386.jpg  00004997.jpg  00005606.jpg  00006211.jpg  00006817.jpg  00007419.jpg  00008006.jpg  00008607.jpg  00009218.jpg  00009828.jpg  00010440.jpg  00011051.jpg  00011626.jpg
00000186.jpg  00000782.jpg  00001394.jpg  00001995.jpg  00002602.jpg  00003205.jpg  00003807.jpg  00004408.jpg  00005019.jpg  00005627.jpg  00006233.jpg  00006838.jpg  00007440.jpg  00008027.jpg  00008629.jpg  00009239.jpg  00009850.jpg  00010462.jpg  00011072.jpg
00000206.jpg  00000804.jpg  00001416.jpg  00002016.jpg  00002624.jpg  00003226.jpg  00003828.jpg  00004429.jpg  00005041.jpg  00005649.jpg  00006255.jpg  00006860.jpg  00007461.jpg  00008048.jpg  00008651.jpg  00009261.jpg  00009871.jpg  00010485.jpg  00011094.jpg
00000226.jpg  00000825.jpg  00001437.jpg  00002038.jpg  00002646.jpg  00003248.jpg  00003849.jpg  00004451.jpg  00005063.jpg  00005670.jpg  00006277.jpg  00006882.jpg  00007482.jpg  00008069.jpg  00008673.jpg  00009282.jpg  00009893.jpg  00010507.jpg  00011116.jpg
00000246.jpg  00000847.jpg  00001459.jpg  00002060.jpg  00002667.jpg  00003269.jpg  00003870.jpg  00004473.jpg  00005085.jpg  00005692.jpg  00006298.jpg  00006903.jpg  00007504.jpg  00008090.jpg  00008695.jpg  00009304.jpg  00009914.jpg  00010528.jpg  00011137.jpg
00000267.jpg  00000869.jpg  00001480.jpg  00002082.jpg  00002689.jpg  00003291.jpg  00003891.jpg  00004495.jpg  00005107.jpg  00005714.jpg  00006320.jpg  00006924.jpg  00007525.jpg  00008112.jpg  00008717.jpg  00009326.jpg  00009936.jpg  00010550.jpg  00011158.jpg
00000287.jpg  00000890.jpg  00001501.jpg  00002104.jpg  00002711.jpg  00003313.jpg  00003913.jpg  00004516.jpg  00005129.jpg  00005735.jpg  00006341.jpg  00006945.jpg  00007546.jpg  00008133.jpg  00008739.jpg  00009347.jpg  00009958.jpg  00010572.jpg  00011180.jpg
00000308.jpg  00000912.jpg  00001523.jpg  00002126.jpg  00002732.jpg  00003334.jpg  00003934.jpg  00004538.jpg  00005151.jpg  00005757.jpg  00006363.jpg  00006967.jpg  00007567.jpg  00008154.jpg  00008761.jpg  00009369.jpg  00009980.jpg  00010594.jpg  00011201.jpg
00000329.jpg  00000934.jpg  00001544.jpg  00002148.jpg  00002754.jpg  00003356.jpg  00003955.jpg  00004560.jpg  00005173.jpg  00005779.jpg  00006385.jpg  00006988.jpg  00007588.jpg  00008175.jpg  00008783.jpg  00009391.jpg  00010002.jpg  00010615.jpg  00011222.jpg
00000350.jpg  00000956.jpg  00001566.jpg  00002170.jpg  00002776.jpg  00003378.jpg  00003977.jpg  00004582.jpg  00005195.jpg  00005801.jpg  00006407.jpg  00007010.jpg  00007609.jpg  00008197.jpg  00008805.jpg  00009413.jpg  00010024.jpg  00010637.jpg  00011243.jpg
00000371.jpg  00000977.jpg  00001587.jpg  00002191.jpg  00002797.jpg  00003399.jpg  00003998.jpg  00004603.jpg  00005217.jpg  00005822.jpg  00006429.jpg  00007031.jpg  00007631.jpg  00008218.jpg  00008827.jpg  00009434.jpg  00010046.jpg  00010659.jpg  00011264.jpg
00000393.jpg  00000999.jpg  00001608.jpg  00002213.jpg  00002819.jpg  00003421.jpg  00004019.jpg  00004625.jpg  00005239.jpg  00005844.jpg  00006451.jpg  00007052.jpg  00007652.jpg  00008239.jpg  00008848.jpg  00009456.jpg  00010068.jpg  00010681.jpg  00011285.jpg
00000413.jpg  00001021.jpg  00001630.jpg  00002235.jpg  00002840.jpg  00003443.jpg  00004040.jpg  00004648.jpg  00005261.jpg  00005866.jpg  00006473.jpg  00007074.jpg  00007673.jpg  00008260.jpg  00008870.jpg  00009478.jpg  00010090.jpg  00010703.jpg  00011306.jpg
00000435.jpg  00001043.jpg  00001651.jpg  00002257.jpg  00002861.jpg  00003465.jpg  00004062.jpg  00004670.jpg  00005282.jpg  00005887.jpg  00006495.jpg  00007095.jpg  00007694.jpg  00008281.jpg  00008892.jpg  00009500.jpg  00010111.jpg  00010725.jpg  00011327.jpg
00000457.jpg  00001065.jpg  00001673.jpg  00002278.jpg  00002882.jpg  00003486.jpg  00004083.jpg  00004692.jpg  00005304.jpg  00005909.jpg  00006517.jpg  00007117.jpg  00007714.jpg  00008303.jpg  00008914.jpg  00009522.jpg  00010133.jpg  00010747.jpg  00011347.jpg
00000479.jpg  00001087.jpg  00001695.jpg  00002300.jpg  00002904.jpg  00003508.jpg  00004105.jpg  00004714.jpg  00005325.jpg  00005930.jpg  00006539.jpg  00007139.jpg  00007735.jpg  00008325.jpg  00008936.jpg  00009543.jpg  00010155.jpg  00010769.jpg  00011368.jpg
00000501.jpg  00001109.jpg  00001716.jpg  00002322.jpg  00002925.jpg  00003529.jpg  00004126.jpg  00004735.jpg  00005347.jpg  00005952.jpg  00006560.jpg  00007160.jpg  00007756.jpg  00008346.jpg  00008958.jpg  00009565.jpg  00010177.jpg  00010791.jpg  00011388.jpg
00000522.jpg  00001132.jpg  00001738.jpg  00002344.jpg  00002947.jpg  00003551.jpg  00004148.jpg  00004757.jpg  00005368.jpg  00005973.jpg  00006581.jpg  00007182.jpg  00007777.jpg  00008368.jpg  00008980.jpg  00009587.jpg  00010198.jpg  00010812.jpg  00011409.jpg
00000544.jpg  00001154.jpg  00001759.jpg  00002365.jpg  00002968.jpg  00003572.jpg  00004169.jpg  00004779.jpg  00005390.jpg  00005995.jpg  00006603.jpg  00007203.jpg  00007798.jpg  00008390.jpg  00009002.jpg  00009609.jpg  00010220.jpg  00010834.jpg  00011429.jpg
00000566.jpg  00001176.jpg  00001780.jpg  00002387.jpg  00002990.jpg  00003593.jpg  00004191.jpg  00004800.jpg  00005411.jpg  00006016.jpg  00006624.jpg  00007225.jpg  00007819.jpg  00008411.jpg  00009024.jpg  00009631.jpg  00010242.jpg  00010855.jpg  00011449.jpg
root@ip-10-10-53-81:~/Rooms/securityfootage# 
root@ip-10-10-53-81:~/Rooms/securityfootage# ffmpeg -framerate 5 -pattern_type glob -i 'mjpeg_carve/jpg/*.jpg' -c:v libx264 -pix_fmt yuv420p out.mp4
ffmpeg version 4.2.7-0ubuntu0.1 Copyright (c) 2000-2022 the FFmpeg developers
  built with gcc 9 (Ubuntu 9.4.0-1ubuntu1~20.04.1)
  configuration: --prefix=/usr --extra-version=0ubuntu0.1 --toolchain=hardened --libdir=/usr/lib/x86_64-linux-gnu --incdir=/usr/include/x86_64-linux-gnu --arch=amd64 --enable-gpl --disable-stripping --enable-avresample --disable-filter=resample --enable-avisynth --enable-gnutls --enable-ladspa --enable-libaom --enable-libass --enable-libbluray --enable-libbs2b --enable-libcaca --enable-libcdio --enable-libcodec2 --enable-libflite --enable-libfontconfig --enable-libfreetype --enable-libfribidi --enable-libgme --enable-libgsm --enable-libjack --enable-libmp3lame --enable-libmysofa --enable-libopenjpeg --enable-libopenmpt --enable-libopus --enable-libpulse --enable-librsvg --enable-librubberband --enable-libshine --enable-libsnappy --enable-libsoxr --enable-libspeex --enable-libssh --enable-libtheora --enable-libtwolame --enable-libvidstab --enable-libvorbis --enable-libvpx --enable-libwavpack --enable-libwebp --enable-libx265 --enable-libxml2 --enable-libxvid --enable-libzmq --enable-libzvbi --enable-lv2 --enable-omx --enable-openal --enable-opencl --enable-opengl --enable-sdl2 --enable-libdc1394 --enable-libdrm --enable-libiec61883 --enable-nvenc --enable-chromaprint --enable-frei0r --enable-libx264 --enable-shared
  libavutil      56. 31.100 / 56. 31.100
  libavcodec     58. 54.100 / 58. 54.100
  libavformat    58. 29.100 / 58. 29.100
  libavdevice    58.  8.100 / 58.  8.100
  libavfilter     7. 57.100 /  7. 57.100
  libavresample   4.  0.  0 /  4.  0.  0
  libswscale      5.  5.100 /  5.  5.100
  libswresample   3.  5.100 /  3.  5.100
  libpostproc    55.  5.100 / 55.  5.100
Input #0, image2, from 'mjpeg_carve/jpg/*.jpg':
  Duration: 00:01:48.20, start: 0.000000, bitrate: N/A
    Stream #0:0: Video: mjpeg (Baseline), yuvj420p(pc, bt470bg/unknown/unknown), 640x480 [SAR 1:1 DAR 4:3], 5 fps, 5 tbr, 5 tbn, 5 tbc
Stream mapping:
  Stream #0:0 -> #0:0 (mjpeg (native) -> h264 (libx264))
Press [q] to stop, [?] for help
[swscaler @ 0x55c775e6a900] deprecated pixel format used, make sure you did set range correctly
[libx264 @ 0x55c775de3d80] using SAR=1/1
[libx264 @ 0x55c775de3d80] using cpu capabilities: MMX2 SSE2Fast SSSE3 SSE4.2 AVX FMA3 BMI2 AVX2
[libx264 @ 0x55c775de3d80] profile High, level 2.2
[libx264 @ 0x55c775de3d80] 264 - core 155 r2917 0a84d98 - H.264/MPEG-4 AVC codec - Copyleft 2003-2018 - http://www.videolan.org/x264.html - options: cabac=1 ref=3 deblock=1:0:0 analyse=0x3:0x113 me=hex subme=7 psy=1 psy_rd=1.00:0.00 mixed_ref=1 me_range=16 chroma_me=1 trellis=1 8x8dct=1 cqm=0 deadzone=21,11 fast_pskip=1 chroma_qp_offset=-2 threads=3 lookahead_threads=1 sliced_threads=0 nr=0 decimate=1 interlaced=0 bluray_compat=0 constrained_intra=0 bframes=3 b_pyramid=2 b_adapt=1 b_bias=0 direct=1 weightb=1 open_gop=0 weightp=2 keyint=250 keyint_min=5 scenecut=40 intra_refresh=0 rc_lookahead=40 rc=crf mbtree=1 crf=23.0 qcomp=0.60 qpmin=0 qpmax=69 qpstep=4 ip_ratio=1.40 aq=1:1.00
Output #0, mp4, to 'out.mp4':
  Metadata:
    encoder         : Lavf58.29.100
    Stream #0:0: Video: h264 (libx264) (avc1 / 0x31637661), yuv420p, 640x480 [SAR 1:1 DAR 4:3], q=-1--1, 5 fps, 10240 tbn, 5 tbc
    Metadata:
      encoder         : Lavc58.54.100 libx264
    Side data:
      cpb: bitrate max/min/avg: 0/0/0 buffer size: 0 vbv_delay: -1
frame=  541 fps= 45 q=-1.0 Lsize=    2563kB time=00:01:47.60 bitrate= 195.2kbits/s speed=8.93x    
video:2556kB audio:0kB subtitle:0kB other streams:0kB global headers:0kB muxing overhead: 0.281483%
[libx264 @ 0x55c775de3d80] frame I:3     Avg QP:11.68  size: 13400
[libx264 @ 0x55c775de3d80] frame P:139   Avg QP:14.58  size:  8767
[libx264 @ 0x55c775de3d80] frame B:399   Avg QP:16.97  size:  3404
[libx264 @ 0x55c775de3d80] consecutive B-frames:  0.9%  2.2%  0.0% 96.9%
[libx264 @ 0x55c775de3d80] mb I  I16..4: 26.3% 66.6%  7.0%
[libx264 @ 0x55c775de3d80] mb P  I16..4:  4.9% 25.7%  1.3%  P16..4: 19.7% 14.4% 11.5%  0.0%  0.0%    skip:22.5%
[libx264 @ 0x55c775de3d80] mb B  I16..4:  0.8%  3.1%  0.0%  B16..8: 32.6% 13.3%  3.4%  direct: 7.0%  skip:39.8%  L0:50.4% L1:46.0% BI: 3.7%
[libx264 @ 0x55c775de3d80] 8x8 transform intra:79.4% inter:92.6%
[libx264 @ 0x55c775de3d80] coded y,uvDC,uvAC intra: 53.1% 43.3% 29.9% inter: 9.1% 17.5% 5.6%
[libx264 @ 0x55c775de3d80] i16 v,h,dc,p: 67% 25%  8%  0%
[libx264 @ 0x55c775de3d80] i8 v,h,dc,ddl,ddr,vr,hd,vl,hu: 32% 28% 29%  3%  1%  1%  1%  2%  3%
[libx264 @ 0x55c775de3d80] i4 v,h,dc,ddl,ddr,vr,hd,vl,hu: 55% 29%  9%  1%  1%  1%  2%  1%  1%
[libx264 @ 0x55c775de3d80] i8c dc,h,v,p: 45% 24% 27%  4%
[libx264 @ 0x55c775de3d80] Weighted P-Frames: Y:0.0% UV:0.0%
[libx264 @ 0x55c775de3d80] ref P L0: 53.7%  2.0% 20.5% 23.8%
[libx264 @ 0x55c775de3d80] ref B L0: 72.2% 19.0%  8.7%
[libx264 @ 0x55c775de3d80] ref B L1: 91.5%  8.5%
[libx264 @ 0x55c775de3d80] kb/s:193.48
root@ip-10-10-53-81:~/Rooms/securityfootage# 

```

