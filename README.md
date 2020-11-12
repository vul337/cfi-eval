# CScan and CBench

This repo contains the source code of our CCS'20 paper "Finding Cracks in
Shields: On the Security of Control Flow Integrity Mechanisms".

Both tools are included in the repo: 1) [CScan](./cscan), for measuring the set
of targets reachable from each CFI-protected ICT instruction at runtime; 2)
[CBench](./cscan), for verifying control flow hijacking attacks that could
bypass CFI.

When using CScan or CBench for a publication, please cite our work:

```
@inproceedings{DBLP:conf/ccs/LiWZCYL20,
  author    = {Yuan Li and
               Mingzhe Wang and
               Chao Zhang and
               Xingman Chen and
               Songtao Yang and
               Ying Liu},
  editor    = {Jay Ligatti and
               Xinming Ou and
               Jonathan Katz and
               Giovanni Vigna},
  title     = {Finding Cracks in Shields: On the Security of Control Flow Integrity
               Mechanisms},
  booktitle = {{CCS} '20: 2020 {ACM} {SIGSAC} Conference on Computer and Communications
               Security, Virtual Event, USA, November 9-13, 2020},
  pages     = {1821--1835},
  publisher = {{ACM}},
  year      = {2020},
  url       = {https://doi.org/10.1145/3372297.3417867},
  doi       = {10.1145/3372297.3417867},
  timestamp = {Thu, 05 Nov 2020 10:10:36 +0100},
  biburl    = {https://dblp.org/rec/conf/ccs/LiWZCYL20.bib},
  bibsource = {dblp computer science bibliography, https://dblp.org}
}
```
