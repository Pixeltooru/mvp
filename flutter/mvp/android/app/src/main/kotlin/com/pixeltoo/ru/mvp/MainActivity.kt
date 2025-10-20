package com.pixeltoo.ru.mvp

import android.os.Bundle
import android.util.Log
import io.flutter.embedding.android.FlutterActivity

class MainActivity : FlutterActivity() {
    companion object {
        private const val TAG = "🔷 MVP_CLIENT [ANDROID_ACTIVITY]"
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i(TAG, "onCreate() called")
        super.onCreate(savedInstanceState)
        Log.i(TAG, "onCreate() completed")
    }
    
    override fun onStart() {
        Log.i(TAG, "onStart() called")
        super.onStart()
    }
    
    override fun onResume() {
        Log.i(TAG, "onResume() called - App is now visible")
        super.onResume()
    }
    
    override fun onPause() {
        Log.i(TAG, "onPause() called - App going to background")
        super.onPause()
    }
    
    override fun onStop() {
        Log.i(TAG, "onStop() called")
        super.onStop()
    }
    
    override fun onDestroy() {
        Log.i(TAG, "onDestroy() called")
        super.onDestroy()
    }
    
    override fun onRestart() {
        Log.i(TAG, "onRestart() called - App returning from background")
        super.onRestart()
    }
}
