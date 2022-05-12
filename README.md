<p align="center">
    <img width=100% src="cover.png">
  </a>
</p>
<p align="center"> 🕵️ A machine learning malware analysis framework for Android apps. ☢️ </p>

<br>

DroidDetective is a Python tool for analysing Android applications (APKs) for potential malware related behaviour and configurations. When provided with a path to an application (APK file) Droid Detective will make a prediction (using it's ML model) of if the application is malicious. Features and qualities of Droid Detective include:
- Analysing which of ~330 permissions are specified in the application's ```AndroidManifest.xml``` file. 🙅
- Analysing the number of standard and proprietary permissions in use in the application's ```AndroidManifest.xml``` file. 🧮
- Using a RandomForest machine learning classifier, trained off the above data, from ~14 malware families and ~100 Google Play Store applications. 💻

# 🤖 Getting Started 
## Installation 
All DroidDetective dependencies can be installed manually or via the requirements file, with 

``` bash
pip install -r REQUIREMENTS.txt
```

DroidDetective has been tested on both Windows 10 and Ubuntu 18.0 LTS.

## Usage 
DroidDetective can be run by providing the Python file with an APK as a command line parameter, such as:
```
python DroidDetective.py myAndroidApp.apk
```
If an ```apk_malware.model``` file is not present, then the tooling will first train the model and will require a training set of APKs in both a folder at the root of the project called ```malware``` and another called ```normal```. Once run successfully a result will be printed onto the CLI on if the model has identified the APK to be malicious or benign. An example of this output can be seen below:

```
>> Analysed file 'com.android.camera2.apk', identified as not malware.
```

An additional parameter can be provided to ```DroidDetective.py``` as a Json file to save the results to. If this Json file already exists the results of this run will be appended to the Json file.

```
python DroidDetective.py myAndroidApp.apk output.json
```

An example of what this Json file could look like is as follows: 

```json 
{
    "com.android.camera2": false,
}
```

# ⚗️ Data Science | The ML Model
DroidDetective is a Python tool for analyzing Android applications (APKs) for potential malware related behaviour. This works by training a Random Forest classifier on information derived from both known malware APKs and standard APKs available on the Android app store. This tooling comes pre-trained, however, the model can be re-trained on a new dataset at any time. ⚙️

This model currently uses permissions from an APKs ```AndroidManifest.xml``` file as a feature set. This works by creating a dictionary of [each standard Android permission](https://gist.github.com/Arinerron/1bcaadc7b1cbeae77de0263f4e15156f) and setting the feature to ```1``` if the permission is present in the APK. Similarly, a feature is added for the amount of permissions in use in the manifest and for the amount of unidentified permissions found in the manifest. 

The pre-trained model was trained off approximately 14 malware families (each with one or more APK files), located from [ashisdb's repository](https://github.com/ashishb/android-malware), and approximately 100 normal applications located from the Google Play Store.

The below denotes the statistics for this ML model:

```
Accuracy: 0.9310344827586207
Recall: 0.9166666666666666
Precision: 0.9166666666666666
F-Measure: 0.9166666666666666
```

The top 10 highest weighted features (i.e. Android permissions) used by this model, for identifying malware, can be seen below:

```
android.permission.ACCESS_ALL_DOWNLOADS: 0.123922
android.permission.ACCESS_BLUETOOTH_SHARE: 0.101895
android.permission.ACCESS_CACHE_FILESYSTEM: 0.098359
android.permission.ACCESS_CHECKIN_PROPERTIES: 0.08816
android.permission.ACCESS_CONTENT_PROVIDERS_EXTERNALLY: 0.057042
android.permission.ACCESS_DOWNLOAD_MANAGER: 0.039082
android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED: 0.035955
android.permission.ACCESS_DRM_CERTIFICATES: 0.026399
android.permission.ACCESS_EPHEMERAL_APPS: 0.02199
android.permission.ACCESS_FM_RADIO: 0.021002
```


# 📜 License
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)
