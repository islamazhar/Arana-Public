<h1 align="center">Araña: Discovering and Characterizing Password Guessing Attacks in Practice</h1>

Araña is a tool for identifying  attack campaigns from login logs. We detail the pipeline of this tool in our USENIX Seuciryt 2023 paper [Araña: Discovering and Characterizing Password Guessing Attacks in Practice](https://www.usenix.org/conference/usenixsecurity23/presentation/islam). This repository contains a proof of concept implementation of Araña on the login logs collected via our prior work [Gossamer (USENIX Security 2022)](https://www.usenix.org/conference/usenixsecurity22/presentation/sanusi-bohuk).

Steps to run
----------------------------------------------------
- Create the `ip_feature` table by following instructions inside `ip_feature_table folder`
- To create the Lsets following HFR heuristics and filtering follow the instructions.
- To run the clustering follow the instructions inside the `clustering` folder.

Questions?
---------------------
We are always looking for ways to improve our code and  pipeline of our tool. For any bugs/improvements/questions, please feel free to shoot an email at: [mislam9@wisc.edu](mailto:mislam9@wisc.edu) or create a pull request.

Citations
------------------------------
If you use any part of our code or paper please cite our paper.

```
@inproceedings {islamArayna23,
author = {Mazharul Islam and Marina Sanusi Bohuk and Paul Chung and Thomas Ristenpart and Rahul Chatterjee},
title = {Ara\~{n}a: Discovering and Characterizing Password Guessing Attacks in Practice},
booktitle = {32nd USENIX Security Symposium (USENIX Security 23)},
year = {2023},
isbn = {978-1-939133-37-3},
address = {Anaheim, CA},
pages = {1019--1036},
url = {https://www.usenix.org/conference/usenixsecurity23/presentation/islam},
publisher = {USENIX Association},
month = aug,
}
```
