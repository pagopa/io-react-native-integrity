package com.pagopa.ioreactnativeintegrity

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityToken
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest


class IoReactNativeIntegrityModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  private lateinit var integrityTokenProvider: StandardIntegrityTokenProvider

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
   * [Source](https://developers.google.com/android/reference/com/google/android/gms/common/GoogleApiAvailability#isGooglePlayServicesAvailable(android.content.Context))
   * @param promise - the React Native promise to be resolved.
   * @return a resolved promise which is true if Google Play Services is available, false otherwise.
   */
  @ReactMethod
  fun isPlayServicesAvailable (promise: Promise){
    val result = when (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(reactApplicationContext)) {
      0, 18, 2 -> true
      else -> false
    }
    promise.resolve(result)
  }

  @ReactMethod
  fun prepare(cloudProjectNumber: String, promise: Promise) {
    try {
      val cpn = cloudProjectNumber.toLong()
      val standardIntegrityManager: StandardIntegrityManager =
        IntegrityManagerFactory.createStandard(reactApplicationContext)
      standardIntegrityManager.prepareIntegrityToken(
        StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
          .setCloudProjectNumber(cpn)
          .build()
      )
        .addOnSuccessListener { integrityTokenProvider = it; promise.resolve(null) }
        .addOnFailureListener { promise.reject(it) }
    }catch (_: NumberFormatException){
      ModuleException.WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT.reject(promise)
    }catch (e: Exception){
      ModuleException.PREPARE_FAILED.reject(promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(e)))
    }
  }

  @ReactMethod
  fun requestToken(requestHash: String?, promise: Promise) {
    try {
      val integrityTokenResponse: Task<StandardIntegrityToken> = integrityTokenProvider.request(
        StandardIntegrityTokenRequest.builder()
          .setRequestHash(requestHash)
          .build()
      )
      integrityTokenResponse
        .addOnSuccessListener { response -> promise.resolve((response.token())) }
        .addOnFailureListener { exception -> promise.reject(exception) }
    }catch(_: UninitializedPropertyAccessException){
        ModuleException.PREPARE_NOT_CALLED.reject(promise)
    }
    catch (e: Exception){
      ModuleException.REQUEST_TOKEN_FAILED.reject(promise, Pair(ERROR_USER_INFO_KEY, getExceptionMessageOrEmpty(e)))
    }
  }

  private fun getExceptionMessageOrEmpty(e: Exception): String{
    return e.message ?: ""
  }

  companion object {
    const val NAME = "IoReactNativeIntegrity"
    const val ERROR_USER_INFO_KEY = "error"

    private enum class ModuleException(
      val ex: Exception
    ) {
      WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT(Exception("WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT")),
      PREPARE_FAILED(Exception("PREPARE_TOKEN_EXCEPTION")),
      PREPARE_NOT_CALLED(Exception("PREPARE_NOT_CALLED")),
      REQUEST_TOKEN_FAILED(Exception("REQUEST_TOKEN_FAILED"));

      fun reject(
        promise: Promise, vararg args: Pair<String, String>
      ) {
        exMap(*args).let {
          promise.reject(it.first, ex.message, it.second)
        }
      }

      private fun exMap(vararg args: Pair<String, String>): Pair<String, WritableMap> {
        val writableMap = WritableNativeMap()
        args.forEach { writableMap.putString(it.first, it.second) }
        return Pair(this.ex.message ?: "UNKNOWN", writableMap)
      }
    }
  }
}
