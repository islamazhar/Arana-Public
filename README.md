<h1 align="center">Araña: Discovering and Characterizing Password Guessing Attacks in Practice</h1>

Araña is a tool for identifying high and low volume attack campaigns from login logs. We detail the pipeline of this tool in USENIX 2023 accepted paper [Araña: Discovering and Characterizing Password Guessing Attacks in Practice](https://islamazhar.github.io/files/AranaUsenix23Islam.pdf). This repository contains a proof of concept imeplemtation of Araña on the login logs collected via our prior work [Gossamer (USENIX 2022)](https://www.cs.cornell.edu/~marina/Gossamer.pdf).

Steps to run
----------------------------------------------------
- Create the `ip_feature` table by following instructions inside `ip_feature_table folder`
- To create the Lsets following HFR heuritcis and filtering follow the instructions.
- To run the clustering follow the instructions inside `clustering` folder.

Questions?
---------------------
We are always looking for ways to improve code and  pipeline of our tool. For any bugs/improvements/questions, please feel free to shoot an email at: [mislam9@wisc.edu](mailto:mislam9@wisc.edu) or create a pull request.

Citations
------------------------------
If you use any part of our code or paper please cite our paper.

```
@inproceedings {islamArayna23,
author = {Mazharul Islam and Marina Sanusi Bohuk and Paul Chung and Thomas Ristenpart and Rahul Chatterjee},
title = {Araña: Discovering and Characterizing Password Guessing Attacks in Practice},
booktitle = {32nd USENIX Security Symposium (USENIX Security 23)},
year = {2023},
isbn = {},
address = {},
url = {},
publisher = {USENIX Association}
}
```