# PixSys

Pixel-based Visualisation of Systems and Networks

The PixSys tool was developed as part of our ongoing research into malware dynamic behaviour and propagation analysis. The accompanying paper is "Investigating malware propagation and behaviour using system and network pixel-based visualisation" (currently in review).

Usage:
The <b>202107-malvis.ipynb</b> Jupyter Lab notebook is the main file to use. This calls the extractcsv Python script that converts monitor tool output to CSV data files, and then can be used to create pixel-based visualisation output to convery CPU, RAM, screen, network, and process machine usage patterns. More specific parameters can also be modified in the extractcsv Python script.

Example data is now available, including raw data from the Virtual Machine data collection environment, CSV generated output, and final visualisation results. We provide test data for running samples of WannaCry and NotPetya.

TO-DO:
* Make available a VM instance and configuration details for deploying the test environment for data collection.

Work conducted by <a href="https://github.com/snoozyrests">Jacob Williams</a> and <a href="http://plegg.me.uk">Phil Legg</a>, as part of research with the University of the West of England (UWE Bristol). This work was part-supported by the National Cyber Security Centre (NCSC), UK.

