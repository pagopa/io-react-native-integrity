package com.pagopa.ioreactnativeintegrity

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
import android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import android.security.keystore.KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * React Native bridge for Google Play Integrity API and key attestation.
 * @property integrityTokenProvider the token integrity provider which should be initialized by calling [prepareIntegrityToken]
 * @property keyStore the key store instance used to generate hardware backed keys and get a key attestation via [getAttestation]
 */
class IoReactNativeIntegrityModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  private var integrityTokenProvider: StandardIntegrityTokenProvider? = null

  /**
   * Lazily initialize the keystore manager only when the variable is called,
   * otherwise it won't be created. Once created the same object will be used during
   * its lifecycle.
   */
  private val keyStore: KeyStore? by lazy {
    try {
      KeyStore.getInstance(KEYSTORE_PROVIDER).also {
        it.load(null)
      }
    } catch (e: Exception) {
      null
    }
  }

  /**
   * Get name of the package, required by React Native bridge.
   */
  override fun getName(): String {
    return NAME
  }

  /**
   * Function which returns a resolved promise with a boolean value indicating whether or not
   * Google Play Services is available on the device or not.
   * isGooglePlayServicesAvailable returns status code indicating whether there was an error.
   * Can be one of following in [com.google.android.gms.common.ConnectionResult]:
   * SUCCESS: 0,
   * SERVICE_MISSING:1,
   * SERVICE_UPDATING: 18
   * SERVICE_VERSION_UPDATE_REQUIRED: 2
   * SERVICE_DISABLED: 3
   * SERVICE_INVALID: 9
   * We map SUCCESS, SERVICE_UPDATING, SERVICE_VERSION_UPDATE_REQUIRED (0, 18, 2) to true.
   * SERVICE_MISSING, SERVICE_DISABLED and SERVICE_INVALID (1,3,9) to false.
   * The promise is resolved to true if Google Play Services is available, to false otherwise.
   * [Source](https://developers.google.com/android/reference/com/google/android/gms/common/GoogleApiAvailability#isGooglePlayServicesAvailable(android.content.Context))
   * @param promise the React Native promise to be resolved or reject.
   */
  @ReactMethod
  fun isPlayServicesAvailable(promise: Promise) {
    val status =
      GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(reactApplicationContext)
    val isAvailable = status in listOf(
      ConnectionResult.SUCCESS,
      ConnectionResult.SERVICE_UPDATING,
      ConnectionResult.SERVICE_VERSION_UPDATE_REQUIRED
    )
    promise.resolve(isAvailable)
  }

  /**
   * Preparation step for a [Play Integrity standard API request](https://developer.android.com/google/play/integrity/standard).
   * It prepares the integrity token provider before obtaining the integrity verdict.
   * It should be called well before the moment an integrity verdict is needed, for example
   * when starting the application. It can also be called time to time to refresh it.
   * The React Native promise is resolved with an empty payload on success, otherwise
   * it gets rejected when:
   * - The preparation fails;
   * - The provided [cloudProjectNumber] format is incorrect.
   * @param cloudProjectNumber a Google Cloud project number which is supposed to be composed only by numbers (Long).
   * @param promise the React Native promise to be resolved or rejected.
   */
  @ReactMethod
  fun prepareIntegrityToken(cloudProjectNumber: String, promise: Promise) {
    try {
      val cpn = cloudProjectNumber.toLong()
      val standardIntegrityManager = IntegrityManagerFactory.createStandard(reactApplicationContext)
      standardIntegrityManager.prepareIntegrityToken(
        StandardIntegrityManager.PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cpn)
          .build()
      ).addOnSuccessListener { res -> integrityTokenProvider = res; promise.resolve(null) }
        .addOnFailureListener { ex ->
          ModuleException.PREPARE_FAILED.reject(
            promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(ex))
          )
        }
    } catch (_: NumberFormatException) {
      ModuleException.WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT.reject(promise)
    } catch (e: Exception) {
      ModuleException.PREPARE_FAILED.reject(
        promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(e))
      )
    }
  }

  /**
   * Integrity token request step for a [Play Integrity standard API request](https://developer.android.com/google/play/integrity/standard).
   * It requests an integrity token which is then attached to the request to be protected.
   * It should be called AFTER [prepareIntegrityToken] has been called and resolved successfully.
   * The React Native promise is resolved with with the token as payload or rejected when:
   * - The integrity token request fails;
   * - The [prepareIntegrityToken] function hasn't been called previously.
   * @param requestHash a digest of all relevant request parameters (e.g. SHA256) from the user action or server request that is happening.
   * The max size of this field is 500 bytes. Do not put sensitive information as plain text in this field.
   * @param promise the React Native promise to be resolved or rejected.
   */
  @ReactMethod
  fun requestIntegrityToken(requestHash: String?, promise: Promise) {
    try {
      val integrityTokenResponse = integrityTokenProvider?.request(
        StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
      )
      integrityTokenResponse?.apply {
        addOnSuccessListener { res -> promise.resolve((res.token())) }
        addOnFailureListener { ex ->
          ModuleException.REQUEST_TOKEN_FAILED.reject(
            promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(ex))
          )
        }
      } ?: ModuleException.PREPARE_NOT_CALLED.reject(promise)
    } catch (e: Exception) {
      ModuleException.REQUEST_TOKEN_FAILED.reject(
        promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(e))
      )
    }
  }

  /**
   * Checks whether or not a [PrivateKey] is hardware backed (TEE/StrongBox) or not.
   * Courtesy of @shadowsheep1
   * @param key the [PrivateKey] to be checked.
   * @returns true if the key is hardware backed according to its [security level](https://developer.android.com/reference/android/security/keystore/KeyProperties)
   * with a fallback to the [isInsideSecureHardware](https://developer.android.com/reference/android/security/keystore/KeyInfo#isInsideSecureHardware())
   * for version codes older than [Build.VERSION_CODES.S].
   * False otherwise.
   */
  private fun isKeyHardwareBacked(key: PrivateKey): Boolean {
    try {
      val factory = KeyFactory.getInstance(
        key.algorithm, KEYSTORE_PROVIDER
      )
      val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
      return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        //
        keyInfo.securityLevel == SECURITY_LEVEL_TRUSTED_ENVIRONMENT || keyInfo.securityLevel == SECURITY_LEVEL_STRONGBOX || keyInfo.securityLevel == SECURITY_LEVEL_UNKNOWN_SECURE
      } else {
        @Suppress("DEPRECATION") return keyInfo.isInsideSecureHardware
      }
    } catch (e: Exception) {
      return false
    }
  }

  /**
   * Generates an attestation key pair using the [keyStore].
   * @param keyAlias the key alias to generate.
   * @param challenge the public key certificate for this key pair will contain an extension that
   * describes the details of the key's configuration and authorizations, including the
   * [challenge] value.
   * If StrongBox is enabled and the generation fails, the function will retry using TEE.
   * @returns the generated key pair.
   */
  @RequiresApi(Build.VERSION_CODES.N)
  private fun generateAttestationKeyWithFallback(keyAlias: String, challenge: ByteArray): KeyPair {
    val hasStrongBox =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && reactApplicationContext.packageManager.hasSystemFeature(
        PackageManager.FEATURE_STRONGBOX_KEYSTORE
      )
    return try {
      // Generate the attestation key using StrongBox if available
      generateAttestationKey(keyAlias, challenge, hasStrongBox)
    } catch (e: Exception) {
      // If the generation fails, we can retry the generation using TEE instead of StrongBox
      // If the generation fails again we throw the exception
      if (hasStrongBox) {
        Log.w(name, "StrongBox Key Generation Failed, retrying with TEE")
        generateAttestationKey(keyAlias, challenge, false)
      } else {
        // If StrongBox has not been used we throw back the error to the caller
        throw Exception("KeyPair Failed Without Fallback", e)
      }
    }
  }

  /**
   * Generates an attestation key pair using the [keyStore].
   * @param keyAlias the key alias to generate.
   * @param challenge the public key certificate for this key pair will contain an extension that
   * describes the details of the key's configuration and authorizations, including the
   * [challenge] value.
   * If the key is in secure hardware, and if the secure hardware supports attestation,
   * the certificate will be signed by a chain of certificates rooted at a trustworthy CA key.
   * Otherwise the chain will be rooted at an untrusted certificate.
   * @param hasStrongBox indicates whether or not the key pair will be stored using StrongBox.
   * @returns the generated key pair.
   */
  @RequiresApi(Build.VERSION_CODES.N)
  private fun generateAttestationKey(
    keyAlias: String, challenge: ByteArray, hasStrongBox: Boolean
  ): KeyPair {
    val builder = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")) // P-256
      .setDigests(KeyProperties.DIGEST_SHA256).setKeySize(256).setAttestationChallenge(challenge)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && hasStrongBox) {
      builder.setIsStrongBoxBacked(true)
      /**
       * We are currently not using this access policy due to a bug in Android 14 and below which
       * prevents the key to be accessed in some scenarios like unlocking with face recognition.
       * More (here)[https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUnlockedDeviceRequired(boolean)]
       * It will be enabled only for Android 15 later when we can thoroughly test this.
       * builder.setUnlockedDeviceRequired(true)
       */
    }
    val keyPairGenerator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER
    )
    keyPairGenerator.initialize(builder.build())
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Gets the keypair for a given keyTag.
   * @param keyTag the keyTag associated with the key pair
   * @return the KeyPair associated with the given keyTag. if the keyTag doesn't exists, or an
   * exception occurs, it returns null.
   */
  private fun getKeyPair(keyTag: String): KeyPair? {
    try {
      keyStore?.let {
        val privateKey = it.getKey(keyTag, null) as? PrivateKey
        privateKey?.also { _ ->
          val publicKey = it.getCertificate(keyTag).publicKey
          return KeyPair(publicKey, privateKey)
        }
      }
      return null
    } catch (_: Exception) {
      return null
    }
  }

  private fun keyExists(keyTag: String) = getKeyPair(keyTag) != null

  /**
   * Generates a (Key Attestation)[https://developer.android.com/privacy-and-security/security-key-attestation].
   * During key attestation, a key pair is generated along with its certificate chain,
   * which can be used to verify the properties of that key pair.
   * If the device supports hardware-level key attestation,
   * the root certificate of the chain is signed using an attestation root key
   * protected by the device's hardware-backed keystore.
   * The promise is resolved with the chain or rejected when:
   * - The device doesn't support key attestation;
   * - The generated key pair is not hardware backed;
   * - The [challenge] exceeds the size of 128 bytes;
   * - The key attestation generation fails.
   * @param challenge the challenge to be included which has a max size of 128 bytes.
   * @param keyAlias key alias for the generated key pair.
   * @param promise the React Native promise to be resolved or rejected.
   */
  @ReactMethod
  fun getAttestation(challenge: String, keyAlias: String, promise: Promise) {
    Thread {
      try {
        // Remove this block if the minSdkVersion is set to 24
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
          ModuleException.UNSUPPORTED_DEVICE.reject(promise)
          return@Thread
        }
        if (keyExists(keyAlias)) {
          ModuleException.KEY_ALREADY_EXISTS.reject(promise)
          return@Thread
        }
        val keyPair = generateAttestationKeyWithFallback(keyAlias, challenge.toByteArray())
        if (!isKeyHardwareBacked(keyPair.private)) {
          // We check if the key is hardware backed just to be sure exclude software fallback
          ModuleException.KEY_IS_NOT_HARDWARE_BACKED.reject(promise)
          return@Thread
        }
        keyStore?.let {
          val chain = it.getCertificateChain(keyAlias)
          // The certificate chain consists of an array of certificates, thus we concat them into a string
          var attestations = arrayOf<String>()
          chain.forEachIndexed { _, certificate ->
            val cert = Base64.encodeToString(certificate.encoded, Base64.DEFAULT)
            attestations += cert
          }
          val concatenatedAttestations = attestations.joinToString(",")
          val encodedAttestation =
            Base64.encodeToString(concatenatedAttestations.toByteArray(), Base64.DEFAULT)
          promise.resolve(encodedAttestation)
        } ?: ModuleException.KEYSTORE_NOT_INITIALIZED.reject(
          promise
        )
      } catch (e: Exception) {
        ModuleException.REQUEST_ATTESTATION_FAILED.reject(
          promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(e))
        )
      }
    }.start()
  }

  /**
   * Extracts a message from an [Exception] with an empty string as fallback.
   * @param e an exception.
   * @return [e] message field or an empty string otherwise.
   */
  private fun getExceptionMessageOrEmpty(e: Exception): String {
    return e.message ?: ""
  }

  companion object {
    const val NAME = "IoReactNativeIntegrity"
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    const val ERROR_USER_INFO_KEY = "error"

    /**
     * Custom exceptions related to failure points.
     * Each enum constant encapsulates a specific exception with an associated error message.
     *
     * @property ex the exception instance associated with the enum constant.
     */
    private enum class ModuleException(
      val ex: Exception
    ) {
      WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT(Exception("WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT")), PREPARE_FAILED(
        Exception("PREPARE_TOKEN_EXCEPTION")
      ),
      PREPARE_NOT_CALLED(Exception("PREPARE_NOT_CALLED")), REQUEST_TOKEN_FAILED(Exception("REQUEST_TOKEN_FAILED")), REQUEST_ATTESTATION_FAILED(
        Exception("REQUEST_ATTESTATION_FAILED")
      ),
      KEY_IS_NOT_HARDWARE_BACKED(Exception("KEY_IS_NOT_HARDWARE_BACKED")), UNSUPPORTED_DEVICE(
        Exception("UNSUPPORTED_DEVICE")
      ),
      KEY_ALREADY_EXISTS(Exception("KEY_ALREADY_EXISTS")), KEYSTORE_NOT_INITIALIZED(Exception("KEYSTORE_NOT_INITIALIZED"));

      /**
       * Rejects the provided promise with the appropriate error message and additional data.
       *
       * @param promise the promise to be rejected.
       * @param args additional key-value pairs of data to be passed along with the error.
       */
      fun reject(
        promise: Promise, vararg args: Pair<String, String>
      ) {
        exMap(*args).let {
          promise.reject(it.first, ex.message, it.second)
        }
      }

      /**
       * Maps the additional key-value pairs of data to a pair containing the error message
       * and a WritableMap of the additional data.
       *
       * @param args additional key-value pairs of data.
       * @return A pair containing the error message and a WritableMap of the additional data.
       */
      private fun exMap(vararg args: Pair<String, String>): Pair<String, WritableMap> {
        val writableMap = WritableNativeMap()
        args.forEach { writableMap.putString(it.first, it.second) }
        return Pair(this.ex.message ?: "UNKNOWN", writableMap)
      }
    }
  }
}
