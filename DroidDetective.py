import json
import os
import pickle
import sys
from datetime import datetime

import pandas as pd
from androguard.misc import AnalyzeAPK
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


class APK_Analyser():
    '''
    Main class for analysing Android APK, using a random forest classifier for identifying if malware
    '''

    # This list is used to define all colums being analysed
    colums = ['android.permission.ACCESS_ALL_DOWNLOADS',
                                        'android.permission.ACCESS_BLUETOOTH_SHARE',
                                        'android.permission.ACCESS_CACHE_FILESYSTEM',
                                        'android.permission.ACCESS_CHECKIN_PROPERTIES',
                                        'android.permission.ACCESS_CONTENT_PROVIDERS_EXTERNALLY',
                                        'android.permission.ACCESS_DOWNLOAD_MANAGER',
                                        'android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED',
                                        'android.permission.ACCESS_DRM_CERTIFICATES',
                                        'android.permission.ACCESS_EPHEMERAL_APPS',
                                        'android.permission.ACCESS_FM_RADIO',
                                        'android.permission.ACCESS_INPUT_FLINGER',
                                        'android.permission.ACCESS_KEYGUARD_SECURE_STORAGE',
                                        'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS',
                                        'android.permission.ACCESS_MOCK_LOCATION',
                                        'android.permission.ACCESS_MTP',
                                        'android.permission.ACCESS_NETWORK_CONDITIONS',
                                        'android.permission.ACCESS_NETWORK_STATE',
                                        'android.permission.ACCESS_NOTIFICATIONS',
                                        'android.permission.ACCESS_NOTIFICATION_POLICY',
                                        'android.permission.ACCESS_PDB_STATE',
                                        'android.permission.ACCESS_SURFACE_FLINGER',
                                        'android.permission.ACCESS_VOICE_INTERACTION_SERVICE',
                                        'android.permission.ACCESS_VR_MANAGER',
                                        'android.permission.ACCESS_WIFI_STATE',
                                        'android.permission.ACCESS_WIMAX_STATE',
                                        'android.permission.ACCOUNT_MANAGER',
                                        'android.permission.ALLOW_ANY_CODEC_FOR_PLAYBACK',
                                        'android.permission.ASEC_ACCESS',
                                        'android.permission.ASEC_CREATE',
                                        'android.permission.ASEC_DESTROY',
                                        'android.permission.ASEC_MOUNT_UNMOUNT',
                                        'android.permission.ASEC_RENAME',
                                        'android.permission.AUTHENTICATE_ACCOUNTS',
                                        'android.permission.BACKUP',
                                        'android.permission.BATTERY_STATS',
                                        'android.permission.BIND_ACCESSIBILITY_SERVICE',
                                        'android.permission.BIND_APPWIDGET',
                                        'android.permission.BIND_CARRIER_MESSAGING_SERVICE',
                                        'android.permission.BIND_CARRIER_SERVICES',
                                        'android.permission.BIND_CHOOSER_TARGET_SERVICE',
                                        'android.permission.BIND_CONDITION_PROVIDER_SERVICE',
                                        'android.permission.BIND_CONNECTION_SERVICE',
                                        'android.permission.BIND_DEVICE_ADMIN',
                                        'android.permission.BIND_DIRECTORY_SEARCH',
                                        'android.permission.BIND_DREAM_SERVICE',
                                        'android.permission.BIND_INCALL_SERVICE',
                                        'android.permission.BIND_INPUT_METHOD',
                                        'android.permission.BIND_INTENT_FILTER_VERIFIER',
                                        'android.permission.BIND_JOB_SERVICE',
                                        'android.permission.BIND_KEYGUARD_APPWIDGET',
                                        'android.permission.BIND_MIDI_DEVICE_SERVICE',
                                        'android.permission.BIND_NFC_SERVICE',
                                        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE',
                                        'android.permission.BIND_NOTIFICATION_RANKER_SERVICE',
                                        'android.permission.BIND_PACKAGE_VERIFIER',
                                        'android.permission.BIND_PRINT_RECOMMENDATION_SERVICE',
                                        'android.permission.BIND_PRINT_SERVICE',
                                        'android.permission.BIND_PRINT_SPOOLER_SERVICE',
                                        'android.permission.BIND_QUICK_SETTINGS_TILE',
                                        'android.permission.BIND_REMOTEVIEWS',
                                        'android.permission.BIND_REMOTE_DISPLAY',
                                        'android.permission.BIND_ROUTE_PROVIDER',
                                        'android.permission.BIND_RUNTIME_PERMISSION_PRESENTER_SERVICE',
                                        'android.permission.BIND_SCREENING_SERVICE',
                                        'android.permission.BIND_TELECOM_CONNECTION_SERVICE',
                                        'android.permission.BIND_TEXT_SERVICE',
                                        'android.permission.BIND_TRUST_AGENT',
                                        'android.permission.BIND_TV_INPUT',
                                        'android.permission.BIND_TV_REMOTE_SERVICE',
                                        'android.permission.BIND_VOICE_INTERACTION',
                                        'android.permission.BIND_VPN_SERVICE',
                                        'android.permission.BIND_VR_LISTENER_SERVICE',
                                        'android.permission.BIND_WALLPAPER',
                                        'android.permission.BLUETOOTH',
                                        'android.permission.BLUETOOTH_ADMIN',
                                        'android.permission.BLUETOOTH_MAP',
                                        'android.permission.BLUETOOTH_PRIVILEGED',
                                        'android.permission.BLUETOOTH_STACK',
                                        'android.permission.BRICK',
                                        'android.permission.BROADCAST_CALLLOG_INFO',
                                        'android.permission.BROADCAST_NETWORK_PRIVILEGED',
                                        'android.permission.BROADCAST_PACKAGE_REMOVED',
                                        'android.permission.BROADCAST_PHONE_ACCOUNT_REGISTRATION',
                                        'android.permission.BROADCAST_SMS',
                                        'android.permission.BROADCAST_STICKY',
                                        'android.permission.BROADCAST_WAP_PUSH',
                                        'android.permission.android.permission.ACCESS_ALL_DOWNLOADS',
                                        'android.permission.CACHE_CONTENT',
                                        'android.permission.CALL_PRIVILEGED',
                                        'android.permission.CAMERA_DISABLE_TRANSMIT_LED',
                                        'android.permission.CAMERA_SEND_SYSTEM_EVENTS',
                                        'android.permission.CAPTURE_AUDIO_HOTWORD',
                                        'android.permission.CAPTURE_AUDIO_OUTPUT',
                                        'android.permission.CAPTURE_SECURE_VIDEO_OUTPUT',
                                        'android.permission.CAPTURE_TV_INPUT',
                                        'android.permission.CAPTURE_VIDEO_OUTPUT',
                                        'android.permission.CARRIER_FILTER_SMS',
                                        'android.permission.CHANGE_APP_IDLE_STATE',
                                        'android.permission.CHANGE_BACKGROUND_DATA_SETTING',
                                        'android.permission.CHANGE_COMPONENT_ENABLED_STATE',
                                        'android.permission.CHANGE_CONFIGURATION',
                                        'android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST',
                                        'android.permission.CHANGE_NETWORK_STATE',
                                        'android.permission.CHANGE_WIFI_MULTICAST_STATE',
                                        'android.permission.CHANGE_WIFI_STATE',
                                        'android.permission.CHANGE_WIMAX_STATE',
                                        'android.permission.CLEAR_APP_CACHE',
                                        'android.permission.CLEAR_APP_GRANTED_URI_PERMISSIONS',
                                        'android.permission.CLEAR_APP_USER_DATA',
                                        'android.permission.CONFIGURE_DISPLAY_COLOR_TRANSFORM',
                                        'android.permission.CONFIGURE_WIFI_DISPLAY',
                                        'android.permission.CONFIRM_FULL_BACKUP',
                                        'android.permission.CONNECTIVITY_INTERNAL',
                                        'android.permission.CONTROL_INCALL_EXPERIENCE',
                                        'android.permission.CONTROL_KEYGUARD',
                                        'android.permission.CONTROL_LOCATION_UPDATES',
                                        'android.permission.CONTROL_VPN',
                                        'android.permission.CONTROL_WIFI_DISPLAY',
                                        'android.permission.COPY_PROTECTED_DATA',
                                        'android.permission.CREATE_USERS',
                                        'android.permission.CRYPT_KEEPER',
                                        'android.permission.DELETE_CACHE_FILES',
                                        'android.permission.DELETE_PACKAGES',
                                        'android.permission.DEVICE_POWER',
                                        'android.permission.DIAGNOSTIC',
                                        'android.permission.DISABLE_KEYGUARD',
                                        'android.permission.DISPATCH_NFC_MESSAGE',
                                        'android.permission.DISPATCH_PROVISIONING_MESSAGE',
                                        'android.permission.DOWNLOAD_CACHE_NON_PURGEABLE',
                                        'android.permission.DUMP',
                                        'android.permission.DVB_DEVICE',
                                        'android.permission.EXPAND_STATUS_BAR',
                                        'android.permission.FACTORY_TEST',
                                        'android.permission.FILTER_EVENTS',
                                        'android.permission.FLASHLIGHT',
                                        'android.permission.FORCE_BACK',
                                        'android.permission.FORCE_STOP_PACKAGES',
                                        'android.permission.FRAME_STATS',
                                        'android.permission.FREEZE_SCREEN',
                                        'android.permission.GET_ACCOUNTS_PRIVILEGED',
                                        'android.permission.GET_APP_GRANTED_URI_PERMISSIONS',
                                        'android.permission.GET_APP_OPS_STATS',
                                        'android.permission.GET_DETAILED_TASKS',
                                        'android.permission.GET_INTENT_SENDER_INTENT',
                                        'android.permission.GET_PACKAGE_IMPORTANCE',
                                        'android.permission.GET_PACKAGE_SIZE',
                                        'android.permission.GET_PASSWORD',
                                        'android.permission.GET_PROCESS_STATE_AND_OOM_SCORE',
                                        'android.permission.GET_TASKS',
                                        'android.permission.GET_TOP_ACTIVITY_INFO',
                                        'android.permission.GLOBAL_SEARCH',
                                        'android.permission.GLOBAL_SEARCH_CONTROL',
                                        'android.permission.GRANT_RUNTIME_PERMISSIONS',
                                        'android.permission.HARDWARE_TEST',
                                        'android.permission.HDMI_CEC',
                                        'android.permission.INJECT_EVENTS',
                                        'android.permission.INSTALL_GRANT_RUNTIME_PERMISSIONS',
                                        'android.permission.INSTALL_LOCATION_PROVIDER',
                                        'android.permission.INSTALL_PACKAGES',
                                        'android.permission.INTENT_FILTER_VERIFICATION_AGENT',
                                        'android.permission.INTERACT_ACROSS_USERS',
                                        'android.permission.INTERACT_ACROSS_USERS_FULL',
                                        'android.permission.INTERNAL_SYSTEM_WINDOW',
                                        'android.permission.INTERNET',
                                        'android.permission.INVOKE_CARRIER_SETUP',
                                        'android.permission.KILL_BACKGROUND_PROCESSES',
                                        'android.permission.KILL_UID',
                                        'android.permission.LAUNCH_TRUST_AGENT_SETTINGS',
                                        'android.permission.LOCAL_MAC_ADDRESS',
                                        'android.permission.LOCATION_HARDWARE',
                                        'android.permission.LOOP_RADIO',
                                        'android.permission.MANAGE_ACCOUNTS',
                                        'android.permission.MANAGE_ACTIVITY_STACKS',
                                        'android.permission.MANAGE_APP_OPS_RESTRICTIONS',
                                        'android.permission.MANAGE_APP_TOKENS',
                                        'android.permission.MANAGE_CA_CERTIFICATES',
                                        'android.permission.MANAGE_DEVICE_ADMINS',
                                        'android.permission.MANAGE_DOCUMENTS',
                                        'android.permission.MANAGE_FINGERPRINT',
                                        'android.permission.MANAGE_MEDIA_PROJECTION',
                                        'android.permission.MANAGE_NETWORK_POLICY',
                                        'android.permission.MANAGE_NOTIFICATIONS',
                                        'android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS',
                                        'android.permission.MANAGE_SOUND_TRIGGER',
                                        'android.permission.MANAGE_USB',
                                        'android.permission.MANAGE_USERS',
                                        'android.permission.MANAGE_VOICE_KEYPHRASES',
                                        'android.permission.MASTER_CLEAR',
                                        'android.permission.MEDIA_CONTENT_CONTROL',
                                        'android.permission.MODIFY_APPWIDGET_BIND_PERMISSIONS',
                                        'android.permission.MODIFY_AUDIO_ROUTING',
                                        'android.permission.MODIFY_AUDIO_SETTINGS',
                                        'android.permission.MODIFY_CELL_BROADCASTS',
                                        'android.permission.MODIFY_DAY_NIGHT_MODE',
                                        'android.permission.MODIFY_NETWORK_ACCOUNTING',
                                        'android.permission.MODIFY_PARENTAL_CONTROLS',
                                        'android.permission.MODIFY_PHONE_STATE',
                                        'android.permission.MOUNT_FORMAT_FILESYSTEMS',
                                        'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
                                        'android.permission.MOVE_PACKAGE',
                                        'android.permission.NET_ADMIN',
                                        'android.permission.NET_TUNNELING',
                                        'android.permission.NFC',
                                        'android.permission.NFC_HANDOVER_STATUS',
                                        'android.permission.NOTIFY_PENDING_SYSTEM_UPDATE',
                                        'android.permission.OBSERVE_GRANT_REVOKE_PERMISSIONS',
                                        'android.permission.OEM_UNLOCK_STATE',
                                        'android.permission.OVERRIDE_WIFI_CONFIG',
                                        'android.permission.PACKAGE_USAGE_STATS',
                                        'android.permission.PACKAGE_VERIFICATION_AGENT',
                                        'android.permission.PACKET_KEEPALIVE_OFFLOAD',
                                        'android.permission.PEERS_MAC_ADDRESS',
                                        'android.permission.PERFORM_CDMA_PROVISIONING',
                                        'android.permission.PERFORM_SIM_ACTIVATION',
                                        'android.permission.PERSISTENT_ACTIVITY',
                                        'android.permission.PROCESS_CALLLOG_INFO',
                                        'android.permission.PROCESS_PHONE_ACCOUNT_REGISTRATION',
                                        'android.permission.PROVIDE_TRUST_AGENT',
                                        'android.permission.QUERY_DO_NOT_ASK_CREDENTIALS_ON_BOOT',
                                        'android.permission.READ_BLOCKED_NUMBERS',
                                        'android.permission.READ_DREAM_STATE',
                                        'android.permission.READ_FRAME_BUFFER',
                                        'android.permission.READ_INPUT_STATE',
                                        'android.permission.READ_INSTALL_SESSIONS',
                                        'android.permission.READ_LOGS',
                                        'android.permission.READ_NETWORK_USAGE_HISTORY',
                                        'android.permission.READ_OEM_UNLOCK_STATE',
                                        'android.permission.READ_PRECISE_PHONE_STATE',
                                        'android.permission.READ_PRIVILEGED_PHONE_STATE',
                                        'android.permission.READ_PROFILE',
                                        'android.permission.READ_SEARCH_INDEXABLES',
                                        'android.permission.READ_SOCIAL_STREAM',
                                        'android.permission.READ_SYNC_SETTINGS',
                                        'android.permission.READ_SYNC_STATS',
                                        'android.permission.READ_USER_DICTIONARY',
                                        'android.permission.READ_WIFI_CREDENTIAL',
                                        'android.permission.REAL_GET_TASKS',
                                        'android.permission.REBOOT',
                                        'android.permission.RECEIVE_BLUETOOTH_MAP',
                                        'android.permission.RECEIVE_BOOT_COMPLETED',
                                        'android.permission.RECEIVE_DATA_ACTIVITY_CHANGE',
                                        'android.permission.RECEIVE_EMERGENCY_BROADCAST',
                                        'android.permission.RECEIVE_MEDIA_RESOURCE_USAGE',
                                        'android.permission.RECEIVE_STK_COMMANDS',
                                        'android.permission.RECEIVE_WIFI_CREDENTIAL_CHANGE',
                                        'android.permission.RECOVERY',
                                        'android.permission.REGISTER_CALL_PROVIDER',
                                        'android.permission.REGISTER_CONNECTION_MANAGER',
                                        'android.permission.REGISTER_SIM_SUBSCRIPTION',
                                        'android.permission.REGISTER_WINDOW_MANAGER_LISTENERS',
                                        'android.permission.REMOTE_AUDIO_PLAYBACK',
                                        'android.permission.REMOVE_DRM_CERTIFICATES',
                                        'android.permission.REMOVE_TASKS',
                                        'android.permission.REORDER_TASKS',
                                        'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
                                        'android.permission.REQUEST_INSTALL_PACKAGES',
                                        'android.permission.RESET_FINGERPRINT_LOCKOUT',
                                        'android.permission.RESET_SHORTCUT_MANAGER_THROTTLING',
                                        'android.permission.RESTART_PACKAGES',
                                        'android.permission.RETRIEVE_WINDOW_CONTENT',
                                        'android.permission.RETRIEVE_WINDOW_TOKEN',
                                        'android.permission.REVOKE_RUNTIME_PERMISSIONS',
                                        'android.permission.SCORE_NETWORKS',
                                        'android.permission.SEND_CALL_LOG_CHANGE',
                                        'android.permission.SEND_DOWNLOAD_COMPLETED_INTENTS',
                                        'android.permission.SEND_RESPOND_VIA_MESSAGE',
                                        'android.permission.SEND_SMS_NO_CONFIRMATION',
                                        'android.permission.SERIAL_PORT',
                                        'android.permission.SET_ACTIVITY_WATCHER',
                                        'android.permission.SET_ALWAYS_FINISH',
                                        'android.permission.SET_ANIMATION_SCALE',
                                        'android.permission.SET_DEBUG_APP',
                                        'android.permission.SET_INPUT_CALIBRATION',
                                        'android.permission.SET_KEYBOARD_LAYOUT',
                                        'android.permission.SET_ORIENTATION',
                                        'android.permission.SET_POINTER_SPEED',
                                        'android.permission.SET_PREFERRED_APPLICATIONS',
                                        'android.permission.SET_PROCESS_LIMIT',
                                        'android.permission.SET_SCREEN_COMPATIBILITY',
                                        'android.permission.SET_TIME',
                                        'android.permission.SET_TIME_ZONE',
                                        'android.permission.SET_WALLPAPER',
                                        'android.permission.SET_WALLPAPER_COMPONENT',
                                        'android.permission.SET_WALLPAPER_HINTS',
                                        'android.permission.SHUTDOWN',
                                        'android.permission.SIGNAL_PERSISTENT_PROCESSES',
                                        'android.permission.START_ANY_ACTIVITY',
                                        'android.permission.START_PRINT_SERVICE_CONFIG_ACTIVITY',
                                        'android.permission.START_TASKS_FROM_RECENTS',
                                        'android.permission.STATUS_BAR',
                                        'android.permission.STATUS_BAR_SERVICE',
                                        'android.permission.STOP_APP_SWITCHES',
                                        'android.permission.STORAGE_INTERNAL',
                                        'android.permission.SUBSCRIBED_FEEDS_READ',
                                        'android.permission.SUBSCRIBED_FEEDS_WRITE',
                                        'android.permission.SUBSTITUTE_NOTIFICATION_APP_NAME',
                                        'android.permission.SYSTEM_ALERT_WINDOW',
                                        'android.permission.TABLET_MODE',
                                        'android.permission.TEMPORARY_ENABLE_ACCESSIBILITY',
                                        'android.permission.TETHER_PRIVILEGED',
                                        'android.permission.TRANSMIT_IR',
                                        'android.permission.TRUST_LISTENER',
                                        'android.permission.TV_INPUT_HARDWARE',
                                        'android.permission.TV_VIRTUAL_REMOTE_CONTROLLER',
                                        'android.permission.UPDATE_APP_OPS_STATS',
                                        'android.permission.UPDATE_CONFIG',
                                        'android.permission.UPDATE_DEVICE_STATS',
                                        'android.permission.UPDATE_LOCK',
                                        'android.permission.UPDATE_LOCK_TASK_PACKAGES',
                                        'android.permission.USER_ACTIVITY',
                                        'android.permission.USE_CREDENTIALS',
                                        'android.permission.VIBRATE',
                                        'android.permission.WAKE_LOCK',
                                        'android.permission.WRITE_APN_SETTINGS',
                                        'android.permission.WRITE_BLOCKED_NUMBERS',
                                        'android.permission.WRITE_DREAM_STATE',
                                        'android.permission.WRITE_GSERVICES',
                                        'android.permission.WRITE_MEDIA_STORAGE',
                                        'android.permission.WRITE_PROFILE',
                                        'android.permission.WRITE_SECURE_SETTINGS',
                                        'android.permission.WRITE_SETTINGS',
                                        'android.permission.WRITE_SMS',
                                        'android.permission.WRITE_SOCIAL_STREAM',
                                        'android.permission.WRITE_SYNC_SETTINGS',
                                        'android.permission.WRITE_USER_DICTIONARYCACHE_CONTENT',
                                        'android.permission.WRITE_EXTERNAL_STORAGE',
                                        'android.permission.READ_EXTERNAL_STORAGE',
                                        'android.permission.WRITE_USER_DICTIONARY',
                                        'other_permission',
                                        'num_of_permissions',
                                        'is_malware']
    # Defines the Random Forest model
    model = None

    def unpack_apk(self, apk_path):
        '''
        A function used for extracting ifnormation from an APK file
        :param apk_path:  the path to the APK
        :return: A dictionary of APK data
        '''
        a, d, dx = AnalyzeAPK(apk_path)
        info_data = {
            "package_name": a.get_app_name(),
            "package": a.get_package(),
            "icon": a.get_app_icon(),
            "permissions": a.get_permissions(),
            "activities": a.get_activities(),
            "android_version_code": a.get_androidversion_code(),
            "android_version_name": a.get_androidversion_name(),
            "min_sdk_version": a.get_min_sdk_version(),
            "max_sdk_version": a.get_max_sdk_version(),
            "target_sdk_version": a.get_target_sdk_version(),
            "effective_sdk_version": a.get_effective_target_sdk_version()
        }

        return info_data

    def train_model(self, malware_apks_folder_path, normal_apks_folder_path):
        '''
        Trains the random forest model by getting APKs known as normal and known as malware and extracting the
        defined data from them.
        :param malware_apks_folder_path: a folder containing malware APKs
        :param normal_apks_folder_path: a folder containing normal APKs
        '''

        data_from_apks = []

        # Get normal APKs
        for subdir, dirs, files in os.walk(normal_apks_folder_path):
            for filename in files:
                try:
                    full_path = os.path.join(subdir, filename)
                    print(full_path)
                    if filename.endswith(".apk"):
                        apk_data = self.unpack_apk(full_path)
                        list_of_apk_data = self.apk_variables_to_df_friendly_list(apk_data, is_malware=0)
                        data_from_apks.append(list_of_apk_data)
                except:
                    print("Failed on file {}".format(filename))

        # Get malware APKs
        for subdir, dirs, files in os.walk(malware_apks_folder_path):
            for filename in files:
                try:
                    full_path = os.path.join(subdir, filename)
                    print(full_path)
                    if filename.endswith(".apk"):
                        apk_data = self.unpack_apk(full_path)
                        list_of_apk_data = self.apk_variables_to_df_friendly_list(apk_data, is_malware=1)
                        data_from_apks.append(list_of_apk_data)
                except:
                    print("Failed on file {}".format(filename))

        # create dataframe
        df = pd.DataFrame(columns=self.colums)
        for iterator in range(0, len(data_from_apks)):
            df.loc[iterator] = data_from_apks[iterator]

        feature_data = df
        if "ID" in feature_data.keys():
            feature_data.drop(feature_data.columns[0], axis=1, inplace=True)
        feature_data.reset_index(drop=True, inplace=True)

        y = feature_data[['is_malware']]  # Labels
        X = feature_data.drop(axis=1, labels=['is_malware'])  # Features

        # Split dataset into training set and test set
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)  # 80% training and 20% test

        # Create a Gaussian Classifier
        random_forest = RandomForestClassifier(n_estimators=100, max_depth=50, oob_score=True)

        # Train the model using the training sets y_pred=random_forest.predict(X_test)
        random_forest.fit(X_train, y_train.values.ravel())

        y_pred = random_forest.predict(X_test)

        # Model Accuracy, how often is the classifier correct?
        self.accuracy = metrics.accuracy_score(y_test, y_pred)
        self.recall = metrics.recall_score(y_test, y_pred)
        self.precision = metrics.precision_score(y_test, y_pred)
        self.f_measure = metrics.f1_score(y_test, y_pred)

        print("Accuracy: {}".format(self.accuracy))
        print("Recall: {}".format(self.recall))
        print("Precision: {}".format(self.precision))
        print("F-Measure: {}".format(self.f_measure))

        self.model = random_forest

        self.original_name = "model"
        self.creation_date = datetime.today().strftime('%Y-%m-%d')

        # write model and accuracy to file to file
        model_data = {"model": self.model,
                      "original_name": self.original_name,
                      "creation_date": self.creation_date,
                      "accuracy": self.accuracy,
                      "recall": self.recall,
                      "precision": self.precision,
                      "f1": self.f_measure,
                      }

        pickle.dump(model_data, open("apk_malware.model", "wb"))

    def apk_variables_to_df_friendly_list(self, apk_data, is_malware=0):
        '''
        A function that takes a dict of APK data and converts it to a list of sloats compatable with the random forest
        classifier
        :param apk_data: a dict of APK data
        :param is_malware: a boolean if the data should be classed as malware or not, can also be None if predicting
        :return: a list of floats
        '''

        # set dict to be all values from the set, where the dicts values are 0
        dict_of_apk_permissions = dict((el, 0) for el in self.colums)

        # check what permissions the APK has and set these to 1
        for permission in apk_data["permissions"]:
            if permission in list(self.colums):
                dict_of_apk_permissions[permission] = 1
            else:
                dict_of_apk_permissions["other_permission"] = int(dict_of_apk_permissions["other_permission"]) + 1

        # Add fields for is_malware and the number of permissions
        dict_of_apk_permissions["num_of_permissions"] = len(apk_data["permissions"])
        if is_malware == None:
            dict_of_apk_permissions.pop("is_malware")
        else:
            dict_of_apk_permissions["is_malware"] = is_malware

        # return the dict as a list of it's values
        return list(dict_of_apk_permissions.values())

    def identify(self, apk_location, model_location):
        '''
        Used to identify if a given apk is malware
        :param apk_location: the path to the apk
        :param model_location: the path to the model
        :return:
        '''
        if self.model == None:
            saved_file = pickle.load(open(model_location, "rb"))
            self.model = saved_file["model"]
            self.accuracy = saved_file["accuracy"]
            self.recall = saved_file["recall"]
            self.precision = saved_file["precision"]
            self.f_measure = saved_file["f1"]

        # Loop through all feature importance scores and save to file
        weights = {}
        for iterator in range(len(self.model.feature_importances_)):
            weight = self.model.feature_importances_[iterator]
            weights[self.colums[iterator]] = weight

        sorted_weights = dict(sorted(weights.items(), key=lambda item: item[1]))

        stats_file = open("model_stats.json","w")
        json.dump(sorted_weights, stats_file, indent=4)
        stats_file.close()
        apk_data = self.unpack_apk(apk_path=apk_location)
        list_of_data = self.apk_variables_to_df_friendly_list(apk_data, is_malware=None)
        result = self.model.predict([list_of_data])

        return result[0], apk_data


if __name__ == '__main__':

    # a boolean, if set the ML model will be re-trained
    analyser = APK_Analyser()
    model_path = f"{os.path.dirname(os.path.abspath(__file__))}/apk_malware.model"

    # Check param given
    if len(sys.argv) > 1:
        file_to_check = sys.argv[1]

        if not file_to_check.endswith(".apk"):
            raise Exception("Please provide an .apk file.")


    else:
        raise Exception("Please provide an APK to analyse")

    # Check should train
    if not os.path.isfile(model_path):
        if os.path.isdir("malware") and os.path.isdir("normal"):
            apk_info = analyser.train_model(malware_apks_folder_path="malware", normal_apks_folder_path="normal")
        else:
            raise Exception(
                "When training a model, ensure that a 'malware' and 'normal' folder exist at the root of this project "
                "and that training APKs exist in both folders.")
    # Check if model exists
    if os.path.exists(model_path):

        result, apk_data = analyser.identify(file_to_check, model_path)

        if result == 1:
            print("Analysed file '{}', identified as malware!".format(file_to_check))
        else:
            print("Analysed file '{}', identified as not malware.".format(file_to_check))

        # Second param is dst json file
        if len(sys.argv) > 2:
            dst_file = sys.argv[2]
            if dst_file.endswith(".json"):

                if result == 1:
                    result = True
                else:
                    result = False

                # check if file exists and if so append to the json, if not create new file
                if os.path.isfile(dst_file) and not os.stat(dst_file).st_size == 0:
                    with open(dst_file) as json_file :
                        current_json_data = json.load(json_file)
                        key = apk_data["package"]
                        current_json_data[key] = result
                        data_to_write = current_json_data
                else:
                    data_to_write = {apk_data["package"]: result}

                with open(dst_file, 'w') as fp:
                    json.dump(data_to_write, fp, indent=4)
                print()

            else:
                raise Exception("A destination file was provided but it was not a Json file.")

    else:
        raise Exception("No model found, please train model")
