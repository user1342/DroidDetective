<p align="center">
    <img width=100% src="cover.png">
  </a>
</p>
<p align="center"> 📱 A machine learning malware analysis framework for Android apps. ☢️ </p>

<br>

DroidDetective is a Python tool for analyzing Android applications (APKs) for potential malware related behavior. This works by training a Random Forest classifier on information derived from both known malware APKs and standard APKs available on the Android app store. This tooling comes pre-trained, however, the model can be re-trained on a new dataset at any time. ⚙️

This model currently uses permissions from an APKs ```AndroidManifest.xml``` file as a feature set. This works by creating a dictionary of each standard Android permission and setting the feature to ```1``` if the permission is present in the APK. Similarly, a feature is added for the amount of permissions in use in the manifest and for the amount of unidentified permissions found in the manifest. 

# 🤖 Getting Started 
## Installation 
All DroidDetective dependencies can be installed manually or via the requirements file, with 

``` bash
pip install -r REQUIREMENTS.txt
```
## Usage 
DroidDetective can be run by providing the Python file with an APK as a command line parameter, such as:
```
python DroidDetective.py myAndroidApp.apk
```
If a ```apk_malware.model``` file is not present, then the tooling will first train the model and will require a training set of APKs in both the ```malware``` and ```normal``` folder. Once run successfully a result will be printed onto the CLI on if the model has identified the APK to be malicious or benign.

# 📜 License
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)
