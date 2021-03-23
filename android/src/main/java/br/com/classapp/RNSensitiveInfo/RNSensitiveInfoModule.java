package br.com.classapp.RNSensitiveInfo;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

import static android.app.Activity.RESULT_OK;


public class RNSensitiveInfoModule extends ReactContextBaseJavaModule {

    private KeyguardManager keyguardManager = null;
    private boolean deviceSecure = false;
    private final int REQUEST_CODE_CREDENTIAL = 123;
    private BiometricPrompt.AuthenticationCallback currentCallback = null;
    private FingerprintManager mFingerprintManager;


    public RNSensitiveInfoModule(ReactApplicationContext reactContext) {
        super(reactContext);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mFingerprintManager = (FingerprintManager) reactContext.getSystemService(Context.FINGERPRINT_SERVICE);
            } catch (Exception e) {
                Log.d("RNSensitiveInfo", "Fingerprint not supported");
            }


            this.keyguardManager = reactContext.getSystemService(KeyguardManager.class);
            this.deviceSecure = keyguardManager.isDeviceSecure();
            ActivityEventListener mActivityResultListener = new ActivityEventListener() {
                @Override
                public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
                    if (requestCode == REQUEST_CODE_CREDENTIAL){
                        if (currentCallback != null) {
                             if (resultCode == RESULT_OK){
                                 currentCallback.onAuthenticationSucceeded(null);
                             }else{
                                 currentCallback.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "Canceled");
                             }
                        }
                    }

                    clearCallback();
                }

                @Override
                public void onNewIntent(Intent intent) {

                }
            };
            reactContext.addActivityEventListener(mActivityResultListener);
        }


    }

    private void clearCallback() {
        currentCallback = null;
    }

    @Override
    public String getName() {
        return "RNSensitiveInfo";
    }

    /**
     * Checks whether the device supports Biometric authentication and if the user has
     * enrolled at least one credential.
     *
     * @return true if the user has a biometric capable device and has enrolled
     * one or more credentials
     */
    private boolean hasSetupBiometricCredential() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                int canAuthenticate = biometricManager.canAuthenticate();

                return canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS || deviceSecure;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }


    @ReactMethod
    public void isHardwareDetected(final Promise pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ReactApplicationContext reactApplicationContext = getReactApplicationContext();
            BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
            int canAuthenticate = biometricManager.canAuthenticate();

            pm.resolve(canAuthenticate != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE);
        } else {
            pm.resolve(false);
        }
    }

    @ReactMethod
    public void hasEnrolledFingerprints(final Promise pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && mFingerprintManager != null) {
            pm.resolve(mFingerprintManager.hasEnrolledFingerprints());
        } else {
            pm.resolve(false);
        }
    }

    @ReactMethod
    public void isSensorAvailable(final Promise promise) {
        promise.resolve(hasSetupBiometricCredential());
    }

    @ReactMethod
    public void getItem(String key, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        String value = prefs(name).getString(key, null);

        if (value != null && options.hasKey("touchID") && options.getBoolean("touchID")) {
            boolean showModal = options.hasKey("showModal") && options.getBoolean("showModal");
            HashMap strings = options.hasKey("strings") ? options.getMap("strings").toHashMap() : new HashMap();

            decryptWithAes(value, showModal, strings, pm, null);
        } else {
            pm.resolve(value);
        }
    }

    @ReactMethod
    public void setItem(String key, String value, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        if (options.hasKey("touchID") && options.getBoolean("touchID")) {
            boolean showModal = options.hasKey("showModal") && options.getBoolean("showModal");
            HashMap strings = options.hasKey("strings") ? options.getMap("strings").toHashMap() : new HashMap();

            putExtraWithAES(key, value, prefs(name), showModal, strings, pm, null);
        } else {
            try {
                putExtra(key, value, prefs(name));
                pm.resolve(value);
            } catch (Exception e) {
                Log.d("RNSensitiveInfo", e.getCause().getMessage());
                pm.reject(e);
            }
        }
    }


    @ReactMethod
    public void deleteItem(String key, ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        SharedPreferences.Editor editor = prefs(name).edit();

        editor.remove(key).apply();

        pm.resolve(null);
    }


    @ReactMethod
    public void getAllItems(ReadableMap options, Promise pm) {

        String name = sharedPreferences(options);

        Map<String, ?> allEntries = prefs(name).getAll();
        WritableMap resultData = new WritableNativeMap();

        for (Map.Entry<String, ?> entry : allEntries.entrySet()) {
            String value = entry.getValue().toString();
            resultData.putString(entry.getKey(), value);
        }
        pm.resolve(resultData);
    }



    private SharedPreferences prefs(String name) {
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
                return EncryptedSharedPreferences.create(
                        "secret_shared_prefs",
                        masterKeyAlias,
                        getReactApplicationContext(),
                        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                );
            } else {
                return getReactApplicationContext().getSharedPreferences(name, Context.MODE_PRIVATE);
            }
        } catch (Exception e) {
            return getReactApplicationContext().getSharedPreferences(name, Context.MODE_PRIVATE);
        }

    }

    @NonNull
    private String sharedPreferences(ReadableMap options) {
        String name = options.hasKey("sharedPreferencesName") ? options.getString("sharedPreferencesName") : "shared_preferences";
        if (name == null) {
            name = "shared_preferences";
        }
        return name;
    }


    private void putExtra(String key, Object value, SharedPreferences mSharedPreferences) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        if (value instanceof String) {
            editor.putString(key, (String) value).apply();
        } else if (value instanceof Boolean) {
            editor.putBoolean(key, (Boolean) value).apply();
        } else if (value instanceof Integer) {
            editor.putInt(key, (Integer) value).apply();
        } else if (value instanceof Long) {
            editor.putLong(key, (Long) value).apply();
        } else if (value instanceof Float) {
            editor.putFloat(key, (Float) value).apply();
        }
    }

    private void showDialog(final HashMap strings, final BiometricPrompt.AuthenticationCallback callback) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                Activity activity = getCurrentActivity();
                                if (activity == null) {
                                    callback.onAuthenticationError(BiometricPrompt.ERROR_CANCELED,
                                            strings.containsKey("cancelled") ? strings.get("cancelled").toString() : "Authentication was cancelled");
                                    return;
                                }

                                if (android.os.Build.VERSION.SDK_INT > Build.VERSION_CODES.Q) {
                                //if (false) {
                                    FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                    Executor executor = Executors.newSingleThreadExecutor();
                                    BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, callback);

                                    BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                                            .setDeviceCredentialAllowed(deviceSecure)
                                            .setDescription(strings.containsKey("description") ? strings.get("description").toString() : null)
                                            .setTitle(strings.containsKey("header") ? strings.get("header").toString() : null)
                                            .build();
                                    biometricPrompt.authenticate(promptInfo);
                                }else{
                                    //FALLBACK ANDROID <= 29
                                    String title = strings.containsKey("header") ? strings.get("header").toString() : null;
                                    String description = strings.containsKey("description") ? strings.get("description").toString(): null;

                                    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(title, description);
                                    activity.startActivityForResult(intent, REQUEST_CODE_CREDENTIAL);

                                    currentCallback = callback;
                                }

                            } catch (Exception e) {
                                throw e;
                            }
                        }
                    }
            );
        }
    }


    private void putExtraWithAES(final String key, final String value, final SharedPreferences mSharedPreferences, final boolean showModal, final HashMap strings, final Promise pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M && hasSetupBiometricCredential()) {
            try {

                if (showModal) {
                    class PutExtraWithAESCallback extends BiometricPrompt.AuthenticationCallback {
                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            putExtra(key, value, mSharedPreferences);
                            pm.resolve(value);
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                            pm.reject(String.valueOf(errorCode), errString.toString());
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            getReactApplicationContext().getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                                    .emit("FINGERPRINT_AUTHENTICATION_HELP", "Fingerprint not recognized.");
                        }
                    }

                    showDialog(strings, new PutExtraWithAESCallback());
                }

            } catch (SecurityException e) {
                pm.reject(e);
            } catch (Exception e) {
                pm.reject(e);
            }
        } else {
            pm.reject("Fingerprint not supported", "Fingerprint not supported");
        }
    }

    private void decryptWithAes(final String encrypted, final boolean showModal, final HashMap strings, final Promise pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
                && hasSetupBiometricCredential()) {

            try {

                if (showModal) {
                    class DecryptWithAesCallback extends BiometricPrompt.AuthenticationCallback {
                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            pm.resolve(encrypted);
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                                pm.reject(String.valueOf(errorCode), errString.toString());
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            getReactApplicationContext().getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                                    .emit("FINGERPRINT_AUTHENTICATION_HELP", "Fingerprint not recognized.");
                        }
                    }

                    showDialog(strings, new DecryptWithAesCallback());
                }


            } catch (SecurityException e) {
                pm.reject(e);
            } catch (Exception e) {
                pm.reject(e);
            }
        } else {
            pm.reject("Fingerprint not supported", "Fingerprint not supported");
        }
    }
}
